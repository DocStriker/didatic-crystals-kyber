## Didatic CRYSTALS-Kyber

Este repositório contém um simulador didático para o CRYSTALS-Kyber, também conhecido como ML-KEM, voltado para aprendizagem sobre criptografia pós-quântica.

Antes de usar o arquivo em Python, é recomendável ler o notebook, pois ele apresenta a lógica do projeto de forma visual e explicativa. O notebook serve como introdução conceitual, enquanto o arquivo em Python permite executar a mesma simulação diretamente no terminal.

## Guia de uso do arquivo Python

O script principal é o arquivo Didatic_ML_KEM.py. Para executá-lo, navegue até a pasta do projeto e rode:

```bash
python Didatic_ML_KEM.py
```

Se preferir usar explicitamente o Python 3.11, execute:

```bash
python3.11 Didatic_ML_KEM.py
```

## Instalação do Python 3.11

Se o Python 3.11 não estiver instalado no sistema, siga os passos abaixo:

```bash
sudo apt update
sudo apt install software-properties-common -y

# Utiliza o repositório deadsnakes PPA para instalar as versões do Python
sudo add-apt-repository ppa:deadsnakes/ppa -y
sudo apt update
sudo apt install python3.11 python3.11-venv python3.11-dev -y
```

## Observação

O notebook e o arquivo Python complementam-se: o notebook ajuda na compreensão do fluxo da simulação e o script permite rodar a implementação de maneira direta.
