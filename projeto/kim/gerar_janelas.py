"""
Geração das janelas de entrada do SISSA a partir das mensagens SOME/IP do dataset de Kim et al.

Objetivo
--------
Aplicar ao dataset de Kim et al. o mesmo pipeline de pré-processamento do artigo do SISSA
(preprocess/preprocessor.py), com as adaptações necessárias para dados reais rotulados:

1. Cada captura é dividida em pedaços de 512 mensagens consecutivas, como em preprocess().
2. Cada pedaço recebe uma classe:
     - pedaços da captura benigna: Normal;
     - pedaços de uma captura de ataque com ao menos uma mensagem do nó atacante (IP de origem
       fora do conjunto de IPs do tráfego benigno): classe do ataque daquela captura;
     - pedaços de captura de ataque sem mensagem do atacante: descartados, pois não pertencem
       com segurança a nenhuma classe.
3. Cada pedaço é codificado com as mesmas funções do SISSA (Preprocessor.worker): one-hot de
   err_code e message_type, IPs convertidos em número e normalização de time, src e dst
   dentro do pedaço. O resultado tem 25 atributos por mensagem.
4. As janelas são geradas com utils.split_to_windows (altura 128, passo 7).
5. As classes são igualadas por sorteio, como no preprocess() original, em um número fixo de
   janelas por classe (por decisão do grupo, o mesmo do dataset do artigo: 2.573).
6. A divisão em treino e validação segue train_val_split(): 80/20 por classe, após
   embaralhamento. Como no artigo, o conjunto de validação também é usado como teste.

Entradas
--------
Arquivos .parquet gerados por parse_pcap.py (uma linha por mensagem SOME/IP).

Saídas
------
Diretórios train/ e val/ contendo data.npy (janelas, 128, 25) em float32 e labels.npy (janelas,)
em int64, no mesmo formato lido por sissautils.to_dataloader.
"""

from __future__ import annotations

import os

import numpy as np
import pandas as pd

# Colunas de entrada do SISSA, na ordem do arquivo data/raw/data.csv do artigo
SISSA_COLUMNS = [
    "time", "src", "dst", "method", "length", "client", "session",
    "protocol", "interface", "message_type", "err_code",
]

TAMANHO_PEDACO = 512      # mensagens por pedaço (preprocessor.py, split_dataframe)
ALTURA_JANELA = 128       # mensagens por janela
PASSO_JANELA = 7          # passo entre janelas consecutivas (config/basic.yml)


def codificar_pedaco(pedaco: pd.DataFrame, utils) -> np.ndarray:
    """
    Codifica um pedaço de mensagens exatamente como Preprocessor.worker do SISSA.

    Parâmetros
    ----------
    pedaco : DataFrame com as colunas SISSA_COLUMNS.
    utils  : módulo preprocess.utils do repositório do SISSA.

    Retorna
    -------
    Matriz (mensagens, 25) em float32.
    """
    # O índice precisa iniciar em zero: utils.encoder concatena as colunas one-hot por posição.
    dados = pedaco[SISSA_COLUMNS].reset_index(drop=True)
    dados = utils.encoder(dados, "err_code", utils.err_code_s2vec)
    dados = utils.encoder(dados, "message_type", utils.message_type_s2vec)
    dados[["time"]] = dados[["time"]].apply(utils.normalize_column)
    dados["src"] = dados["src"].apply(utils.ip_to_int)
    dados["dst"] = dados["dst"].apply(utils.ip_to_int)
    dados[["src", "dst"]] = dados[["src", "dst"]].apply(utils.normalize_column)
    return dados.to_numpy().astype(np.float32)


def pedacos_por_classe(pasta_parsed: str, arquivos_por_classe: dict, ips_benignos: set) -> dict:
    """
    Seleciona os pedaços de 512 mensagens de cada classe.

    Parâmetros
    ----------
    pasta_parsed        : pasta com os arquivos .parquet de parse_pcap.py.
    arquivos_por_classe : dicionário {classe: [arquivos .parquet]}; a classe 'Normal' deve
                          conter apenas a captura benigna.
    ips_benignos        : conjunto de IPs de origem do tráfego benigno.

    Retorna
    -------
    Dicionário {classe: lista de DataFrames}, um DataFrame por pedaço selecionado.
    """
    selecionados = {}
    for classe, arquivos in arquivos_por_classe.items():
        pedacos = []
        for arquivo in arquivos:
            tabela = pd.read_parquet(os.path.join(pasta_parsed, arquivo), columns=SISSA_COLUMNS)
            n_pedacos = len(tabela) // TAMANHO_PEDACO
            atacante = ~tabela["src"].isin(ips_benignos).to_numpy()
            for i in range(n_pedacos):
                inicio, fim = i * TAMANHO_PEDACO, (i + 1) * TAMANHO_PEDACO
                if classe == "Normal" or atacante[inicio:fim].any():
                    pedacos.append(tabela.iloc[inicio:fim])
        selecionados[classe] = pedacos
    return selecionados


def montar_dataset(pedacos: dict, classes: list, janelas_por_classe: int, utils,
                   proporcao_treino: float = 0.8, semente: int = 42):
    """
    Gera as janelas de cada classe, iguala as classes por sorteio e divide em treino e validação.

    Parâmetros
    ----------
    pedacos            : saída de pedacos_por_classe.
    classes            : nomes das classes na ordem dos rótulos (índice = rótulo).
    janelas_por_classe : número de janelas sorteadas por classe.
    utils              : módulo preprocess.utils do repositório do SISSA.
    proporcao_treino   : fração de cada classe destinada ao treino (0,8 em train_val_split).
    semente            : semente do gerador aleatório, para reprodutibilidade.

    Retorna
    -------
    (X_treino, y_treino, X_val, y_val) e um DataFrame com as contagens por classe.
    """
    rng = np.random.default_rng(semente)
    janelas_por_pedaco = (TAMANHO_PEDACO - ALTURA_JANELA) // PASSO_JANELA + 1
    treino_X, treino_y, val_X, val_y, contagens = [], [], [], [], []

    for rotulo, classe in enumerate(classes):
        lista = pedacos[classe]
        total = len(lista) * janelas_por_pedaco
        if total < janelas_por_classe:
            raise ValueError(f"{classe}: apenas {total} janelas disponíveis para {janelas_por_classe} pedidas")

        # Sorteio das janelas entre todas as disponíveis da classe (equivalente a gerar todas e
        # sortear, como em preprocess(), mas codificando apenas os pedaços efetivamente usados).
        sorteio = rng.choice(total, size=janelas_por_classe, replace=False)
        por_pedaco = {}
        for indice in sorteio:
            por_pedaco.setdefault(indice // janelas_por_pedaco, []).append(indice % janelas_por_pedaco)

        janelas = []
        for i_pedaco, posicoes in por_pedaco.items():
            todas = utils.split_to_windows(codificar_pedaco(lista[i_pedaco], utils),
                                           window_height=ALTURA_JANELA, step=PASSO_JANELA)
            janelas.append(todas[posicoes])
        janelas = np.concatenate(janelas)

        # Divisão 80/20 por classe após embaralhamento, como em train_val_split()
        rng.shuffle(janelas)
        n_treino = int(len(janelas) * proporcao_treino)
        treino_X.append(janelas[:n_treino])
        val_X.append(janelas[n_treino:])
        treino_y.append(np.full(n_treino, rotulo, dtype=np.int64))
        val_y.append(np.full(len(janelas) - n_treino, rotulo, dtype=np.int64))
        contagens.append({"classe": classe, "rotulo": rotulo, "pedacos_disponiveis": len(lista),
                          "pedacos_usados": len(por_pedaco), "treino": n_treino,
                          "validacao": len(janelas) - n_treino})

    X_treino, y_treino = np.concatenate(treino_X), np.concatenate(treino_y)
    X_val, y_val = np.concatenate(val_X), np.concatenate(val_y)
    # Embaralhamento final dos conjuntos, como em train_val_split()
    p = rng.permutation(len(X_treino))
    q = rng.permutation(len(X_val))
    return X_treino[p], y_treino[p], X_val[q], y_val[q], pd.DataFrame(contagens)


def salvar(pasta_saida: str, X_treino, y_treino, X_val, y_val) -> None:
    """Grava os conjuntos em pasta_saida/train e pasta_saida/val no formato lido pelo SISSA."""
    for nome, X, y in [("train", X_treino, y_treino), ("val", X_val, y_val)]:
        destino = os.path.join(pasta_saida, nome)
        os.makedirs(destino, exist_ok=True)
        np.save(os.path.join(destino, "data.npy"), X)
        np.save(os.path.join(destino, "labels.npy"), y)
