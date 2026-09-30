# Copyright (c) 2026 SevenMatt. Todos os direitos reservados.
# Licenciado sob os termos do arquivo LICENSE na raiz do projeto.


# Uso básico: nome da ferramenta + link
linksentinel https://dominio-suspeito.com/login

# Vários links de uma vez
linksentinel "http://bit.ly/abc" "http://1.2.3.4/payload.exe"

# A partir de arquivo
linksentinel -f urls.txt

# Com chaves de reputação (ou use variáveis de ambiente)
export VT_API_KEY="sua_chave"
export GSB_API_KEY="sua_chave"
linksentinel "https://link-suspeito.com"

# Só o resumo, em lote
linksentinel -f urls.txt --quiet

# Saída JSON (para automação/pipeline)
linksentinel "https://x.com" --json

# Pular etapas lentas
linksentinel "https://x.com" --no-whois --no-redirects

# windows install
pyinstaller --onefile --name linksentinel --collect-all tldextract linksentinel\cli.py

# Install 
pipx install linksentinel
linksentinel --version
