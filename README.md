# Reprodução e extensão do SISSA — Técnicas de Ataque e Detecção de Intrusão (CIn-UFPE, 2026.2)

Projeto da disciplina **CIN0114 – Técnicas de Ataque e Detecção de Intrusão** (Prof. Paulo Freitas), Centro de Informática da UFPE.

Este repositório é um *fork* do código oficial do artigo:

> Q. Liu, X. Li, K. Sun, Y. Li e Y. Liu, "SISSA: Real-Time Monitoring of Hardware Functional Safety and Cybersecurity With In-Vehicle SOME/IP Ethernet Traffic," *IEEE Internet of Things Journal*, vol. 11, n. 16, pp. 27322–27339, 2024.

Repositório original: <https://github.com/jamesnulliu/SISSA> (licença Apache-2.0, mantida em `LICENSE`). Todo o código fora da pasta `projeto/` é dos autores originais, exceto os trechos marcados com `# [PROJETO]`.

## Integrantes

- Gabriel Maciel
- Getúlio Junqueira
- Wenderson Santos

## O que este repositório acrescenta ao original

1. **Reprodução** dos resultados do artigo (Tabelas III, IV e V; Figuras 10, 11 e 12) no dataset dos autores.
2. **Correções de avaliação**: conjunto de teste separado (70/10/20), curvas ROC calculadas com probabilidades, várias seeds e teste estatístico (McNemar).
3. **Avaliação em outro dataset**: tráfego SOME/IP de Kim et al. (2026), com parser de pcap, rotulagem e geração de janelas no formato do SISSA.
4. *(Se houver)* **Melhoria proposta** pela equipe. <!-- TODO: descrever -->

## Estrutura

Tudo o que é do grupo vive dentro de `projeto/`. O restante (`config/`, `models/`, `preprocess/`, `scripts/`, `train.py`, etc.) é o código original dos autores, intocado — exceto onde houver o comentário `# [PROJETO]`.

```
.
├── config/  models/  preprocess/  scripts/     ← original
├── train.py  test.py  data_gen.py  ...          ← original
├── projeto/
│   ├── notebooks/
│   │   ├── 01_reproducao.ipynb              reprodução no dataset original
│   │   ├── 02_dataset_kim.ipynb             SISSA no dataset de Kim et al.
│   │   └── 03_melhoria.ipynb                melhoria proposta (se houver)
│   ├── kim/
│   │   ├── parse_pcap.py                    pcap -> tabela por pacote
│   │   ├── rotular.py                       rótulo por pacote e por janela
│   │   └── gerar_janelas.py                 janelas e divisão treino/val/teste
│   └── resultados/                          tabelas (.csv) e figuras (.png) do relatório
├── .gitignore                                   original + regras do grupo
├── LICENSE                                       original (Apache-2.0)
└── README.md                                     este arquivo
```

## Como reproduzir

Todos os experimentos foram executados no Google Colab com GPU. Basta abrir os notebooks na ordem abaixo e executar todas as células.

| Notebook | O que faz | Abrir |
| --- | --- | --- |
| `projeto/notebooks/01_reproducao.ipynb` | Baixa o dataset original, treina os 6 modelos e gera as tabelas e figuras do artigo | <!-- TODO: link "Open in Colab" --> |
| `projeto/notebooks/02_dataset_kim.ipynb` | Baixa os pcaps de Kim et al., gera as janelas e treina o SISSA | <!-- TODO --> |
| `projeto/notebooks/03_melhoria.ipynb` | Treina e avalia a versão modificada | <!-- TODO --> |

### Dados

- **Dataset original (SISSA):** baixado automaticamente pelo notebook 01 a partir do link do Google Drive divulgado pelos autores.
- **Dataset de Kim et al.:** T. Kim, *SOME/IP traffic (Benign and Attack samples)*, figshare, 2026. DOI: [10.6084/m9.figshare.30970450](https://doi.org/10.6084/m9.figshare.30970450). Licença CC BY 4.0. Baixado automaticamente pelo notebook 02.

Dados, pcaps e pesos **não** são versionados (ver `.gitignore`).

### Pesos treinados

Os pesos (`.pt`) e logs de treino estão em: <!-- TODO: link da pasta do Drive com acesso "qualquer pessoa com o link" -->

## Alterações no código original

| Arquivo | Alteração | Motivo |
| --- | --- | --- |
| <!-- ex.: test.py --> | <!-- ex.: salva probs.npy com as saídas do softmax --> | <!-- ex.: calcular ROC/AUC corretamente --> |

## Resultados principais

<!-- TODO: preencher ao final (tabela artigo vs. reprodução, resultados no dataset de Kim) -->

## Referências

1. Q. Liu *et al.*, "SISSA: Real-Time Monitoring of Hardware Functional Safety and Cybersecurity With In-Vehicle SOME/IP Ethernet Traffic," *IEEE Internet of Things Journal*, vol. 11, n. 16, 2024.
2. T. Kim, H. Park, I. You e B. I. Kwak, "XGBoost-Based Anomaly Detection Framework for SOME/IP in In-Vehicle Networks," *Systems*, vol. 14, n. 2, art. 196, 2026.
3. T. Kim, "SOME/IP traffic (Benign and Attack samples)," figshare, 2026. doi: 10.6084/m9.figshare.30970450.