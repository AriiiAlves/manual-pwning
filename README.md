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
- **Return Oriented Programming** - Encadeia instruções existentes (gadgets) terminadas em ret para construir payloads
  - **Partial Overwrite** - Modifica apenas parte de um endereço para contornar ASLR
  - **Stack Pivoting** - Redireciona a stack para região de memória controlada pelo atacante
  - **SIGROP (SROP)** - Explora sinais Unix usando estrutura sigcontext para controlar registradores
  - **ret2csu** - Usa gadgets em __libc_csu_init para configurar múltiplos argumentos
  - **ret2system** - Retorna para função system() com argumento controlado para obter shell

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