# ARSENAL PESSOAL DE LINUX HARDENING
Este documento inclui tópicos relevantes durante o meu setup pessoal orientado à segurança e privacidade do sistema operacional Arch Linux.

<!-- ### Índice -->
 1. [Kernel](#kernel)
 2. [Kernel hardening por parâmetros de inicialização do kernel](#bootparams)
 3. [Rootless Xorg](#rootlessx11)
 4. [Criando um firewall stateful com o iptables](#iptables)
 5. [Kernel hardening por parâmetros sysctl](#sysctlparams)
 6. [Sandboxing de serviços com systemd sandboxes](#sysdsndb)
 7. [Attack surface reduzida pela proibição de certos módulos](#blacklists)
 8. [Confinamento de programas específicos com AppArmor e bubblewrap](#sandboxingextra)
 9. [LUKS e criptografia negável](#luks)
 10. [Detached /boot e Secure Boot](#integridadeboot)
 11. [Attack surface reduzida pelo minimalismo](#minimalismo)
 12. [Navegador web](#javascriptsucks)
 13. [LibreSSL](#opensslsucks)
 14. [hardened_malloc, um port do malloc do OpenBSD](#mallocopenbsd)
 15. [Atualização do Microcode](#ucode)
 16. [Rede local](#rede)
 
<div id='kernel'/>  

## Kernel
Grande parte desta documentação considera que o usuário esteja utilizando o kernel *linux-hardened*, incluído no repositório oficial sob o pacote extra/linux-hardened. Esta é uma compilação do kernel Linux complacente com o KSPP (Kernel Self Protection Project), compilada a partir da tarball do kernel oficial com os patches de hardening incluídos ao código do kernel por um arquivo .patch e compilado com configurações voltadas à segurança. Apesar dos detalhes, não é necessário se preocupar com a compilação, pois, como mencionado anteriormente, o pacote está no repositório do Arch Linux e pode ser instalado com `sudo pacman -Sy linux-hardened`. Veja abaixo uma lista de **alguns** avanços do projeto linux-hardened sobre o kernel puro:

* Melhorias de ASLR, listadas [neste link do GitHub](https://gist.github.com/thestinger/b43b460cfccfade51b5a2220a0550c35).
* Maior quantidade de sanity checks.
* Sanitização de slabs e kernel pages.
* Slab canaries.
* Traz por padrão configurações sysctl mais estritas.
* Sanitiza alocações de kernel pages e slabs ao desalocar (a fim de evitar use-after-free).
* Adiciona o parâmetro extra_latent_entropy que, se setado como um parâmetro de boot do kernel, faz com que uma entropia maior seja coletada durante o boot.
* Desativa *unprivileged user namespaces* [que expõe grande superfície de ataque ao kernel](https://lists.archlinux.org/pipermail/arch-general/2017-February/043066.html).
* Implementa detecção de *writable function pointers*.
* Configurações padrão orientadas à segurança.
* Alguns patches similares a patches do PaX/Grsec.





<div id='bootparams'/>  

# Kernel hardening por parâmetros de inicialização do kernel
Existem alguns parâmetros de boot do kernel que aprimoram a segurança e podem ser adicionados no arquivo de configuração do seu bootloader. Leia-os abaixo, seguidos de suas respectivas explicações:

### `apparmor=1 security=apparmor`
Habilita o AppArmor no lado do kernel, você ainda precisará do pacote apparmor para operá-lo no userspace.

### `lsm=lockdown,yama,apparmor`
O padrão do linux-hardened é `lockdown,yama`, mas uso o AppArmor também, então preciso incluí-lo.

### `slab_nomerge`
Desativa o merge de slabs. Slabs podem ser usados de forma prejudicial, pois o kernel funde slabs que compartilham o mesmo tamanho e outras características para economia de espaço em memória, [isso é documentado como um facilitador de heap overflow no passado](https://cateee.net/lkddb/web-lkddb/SLAB_MERGE_DEFAULT.html). Com esse parâmetro, reduzimos a superfície de ataque do kernel ao isolar os slabs. 

Isso trará um aumento na utilização de memória pelo kernel. Use slabinfo -a para observar.

### `init_on_alloc=1 init_on_free=1`
São usados na prevenção ao vazamento de informações sensíveis.

*init_on_alloc* fará o kernel inicializar com zeros as páginas e os objetos de heap recém alocados.

*init_on_free* fará o kernel inicializar com zeros as páginas e objetos heap recém desalocados, isso dificultará vazamento de dados caso um atacante explore uma vulnerabilidade de use-after-free em certas partes do kernel.

**NÃO É NECESSÁRIO ATIVAR ESSES PARÂMETROS NO LINUX-HARDENED, ELE É COMPILADO COM *CONFIG_INIT_ON_ALLOC_DEFAULT_ON=y* E *CONFIG_INIT_ON_FREE_DEFAULT_ON=y* E, PORTANTO, JÁ TRAZ ESSES PARÂMETROS ATIVOS.**

### `page_alloc.shuffle=1`
Este parâmetro é necessário para o funcionamento de *CONFIG_SHUFFLE_PAGE_ALLOCATOR*, que aumenta a aleatoriedade da alocação de páginas pelo kernel, diminuindo assim a previsibilidade dessas alocações.

### `slub_debug=F`
Habilita verificações de integridade (F). As verificações de integridade são evidentes e têm um impacto no desempenho, mas não impactam tanto em sistemas modernos e adicionam diversas verificações de integridade às operações de slab do kernel.

Existem duas outras letras que podem ser adicionadas neste parâmetro, mas fica a seu critério, veja:
* Z: O redzoning adicionaria áreas extras ao redor dos slabs que detectariam quando um slab é sobrescrito para além do seu respectivo tamanho real, o que pode ajudar a detectar estouros, o impacto no desempenho é insignificante. **ATIVAR REDZONING NÃO SERIA NECESSÁRIO, POIS O LINUX-HARDENED USA SLAB_CANARY PARA PREVENÇÃO DE OVERFLOWS**
* P: O poisoning gravaria um valor arbitrário em objetos desalocados, portanto, qualquer modificação ou referência a esse objeto após desalocado (ou antes de inicializado) seria detectada e evitada. Isso evitaria muitas possibilidades de use-after-free, além de ter baixo custo em desempenho. **O PROBLEMA COM O POISONING É QUE ELE ACARRETARIA NA DESATIVAÇÃO DE OUTROS PARÂMETROS QUE UTILIZAMOS, POR EXEMPLO, ELE DESATIVARIA O init_on_free=1, NÃO VALERIA A PENA**

### `mce=0`
Útil para sistemas com memória ECC, definir mce=0 causará kernel panic em qualquer erro irreversível detectado pelo ECC (o sistema de exceção de verificação da máquina). Os erros corrigidos com sucesso serão apenas logados. Impactos de desempenho não são esperados.

Sem esse parâmetro, o padrão seria mce=1, que apenas emitiria SIGBUS em erros não reversíveis. Infelizmente, isso significa que processos maliciosos que tentem explorar erros de hardware (como o rowhammer) poderão tentar repetidamente, sofrendo apenas um SIGBUS ao falhar.

### `lockdown=confidentiality`
Coloca o lockdown do kernel em modo confidentiality, esse é o mais agressivo e seguro dos modos do Lockdown. O Lockdown protege o kernel restringindo o acesso que o userspace tem do kernel. 

### `oops=panic`
Interromperá a execução com um kernel panic quando um "oops" ocorrer no kernel, isso é útil porque exploits a nível de kernel podem acabar causando oopsies, então é interessante que oopsies sejam fatais, mas saiba que eles **nem sempre** ocorrem nessas ocasiões de ataque, por exemplo: Um bug inofensivo em um driver pode causar um oops.

### `iommu=force`
Força o uso do IOMMU mesmo quando não necessário. Protege o sistema contra ataques DMA.

### `intel_iommu=on` **ou** `amd_iommu=on`
Ativa o IOMMU, que impede ataques DMA, um tipo de ataque que pode permitir que dados da memória sejam acessados diretamente via hardware.

### `modules.sig_enforce=1`
Permite o carregamento apenas de módulos do kernel assinados com uma assinatura válida e confiável. Qualquer módulo com uma assinatura não confiável ou não assinado NÃO IRÁ SER CARREGADO durante a inicialização. Isso garante a segurança ao dificultar muito o carregamento de código malicioso na forma de módulo do kernel.

Existe um porém: Isso quebrará módulos DKMS que serão impedidos de serem carregados, exemplos disso são os módulos DKMS do VirtualBox e dos drivers proprietários da NVIDIA, então, se você for um usuário NVIDIA e quiser ativar esse parâmetro, tente dar uma chance ao nouveau, por mais difícil que seja. Também seria possível usar o [arch-sign-modules](https://aur.archlinux.org/packages/arch-sign-modules/) para assinar módulos confiáveis que não estejam assinados.

### `pti=on`
Ativa o KPTI (Kernel Page Table Isolation) e impede que o KASLR seja burlado. O KPTI será forçado mesmo em processadores que em teoria não sejam vulneráveis ao Meltdown.

### `spectre_v2=on`
Ativa as mitigações contra Spectre v2. Isso automaticamente ativa `spectre_v2_user=on`, que protege conta IBPB e STIBP.

### `extra_latent_entropy`
Esse parâmetro é exclusivo do linux-hardened e aprimora o gerador de entropia durante o boot.

### `mds=full,nosmt`
Ativa todas as mitigações disponíveis contra a vulnerabilidade MDS. Isso pode impactar no desempenho, pois o valor nosmt desativa o hyperthreading e tecnologias equivalentes, prossiga com cautela.

<div id='rootlessx11'/>  

# Rootless Xorg
O princípio do menor privilégio é extremamente relevante em segurança, controlar firmemente o acesso que cada programa tem no sistema operacional é uma ótima prática, principalmente se tratando de algo massivo como o Xorg. Ao rodar o Xorg sem privilégios de root, rodando-o através do seu usuário comum, minimizas muito o impacto que uma vulnerabilidade RCE teria, por exemplo.

### Basta adicionar o seguinte no arquivo **/etc/X11/Xwrapper.config**:

`needs_root_rights = no`

Após isso, todas as próximas inicializações do seu ambiente desktop estarão rodando sobre um Xorg sem privilégios de root.

Para comprovar que agora o Xorg está rodando através do seu usuário não-root, execute `ps -o user $(pgrep Xorg)`

Outro ponto interessante é prestar atenção na evolução do Wayland e migrar assim que possível, já que por padrão ele é mais seguro que o Xorg.

<div id='iptables'/>  

# Criando um firewall stateful com o iptables
Meu setup pessoal do Arch Linux costuma contar com filtragem de pacotes pelo iptables configurado como um stateful firewall de forma a permitir que NADA chegue na chain INPUT sem que seja um pacote com estado ESTABLISHED, ou seja, pertencente a conexões já estabelecidas.

Inicialmente, vamos setar DROP em todas as chains:

`sudo iptables -P INPUT DROP`

`sudo iptables -P FORWARD DROP`

`sudo iptables -P OUTPUT DROP`

Agora, vamos permitir, como já citado na introdução, apenas pacotes com estado ESTABLISHED de chegarem na chain INPUT:

`sudo iptables -A INPUT -m conntrack --ctstate ESTABLISHED`

A seguir, vamos permitir apenas pacotes com os estados ESTABLISHED, RELATED e NEW na chain OUTPUT:

`sudo iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED,NEW`

E, por fim, vamos permitir conexões de loopback:

`sudo iptables -A INPUT  -i lo -j ACCEPT`

`sudo iptables -A OUTPUT -i lo -j ACCEPT`

Não se esqueça de salvar as regras:

`sudo iptables-save > /etc/iptables/iptables.rules`

Dessa forma, nenhuma conexão de entrada 'espontânea' é permitida, apenas passam pela chain INPUT os pacotes pertencentes a conexões já estabelecidas.

<div id='sysctlparams'/>  

# Kernel hardening por parâmetros sysctl
### `kernel.yama.ptrace_scope = 3`
Habilita a maior restrição provida pelo LSM Yama em relação à chamada PTRACE_ATTACH, dessa forma, nenhum processo pode usar o ptrace com PTRACE_ATTACH e nem via PTRACE_TRACEME.

### `dev.tty.ldisc_autoload = 0`
Sem essa flag, seriam permitidos requisitos diretos do userspace ao carregamento de qualquer TTY line discipline de um módulo do kernel.

### `fs.protected_fifos = 2`
Ativa proteção contra a interação com FIFOs não pertencentes ao usuário em *world writable sticky directories*. 

CVE-2000-1134, CVE-2007-3852, CVE-2008-0525, CVE-2009-0416, CVE-2011-4834, CVE-2015-1838, CVE-2015-7442 e CVE-2016-7489 poderiam ter sido evitadas se essa feature existisse em suas respectivas épocas, [como apontado pelo Linus Torvalds no commit que introduziu essa opção](https://github.com/torvalds/linux/commit/30aba6656f).

### `fs.protected_regular = 2`
Ativa proteção contra a interação com *regular files* não pertencentes ao usuário em *world writable sticky directories*. 

CVE-2000-1134, CVE-2007-3852, CVE-2008-0525, CVE-2009-0416, CVE-2011-4834, CVE-2015-1838, CVE-2015-7442 e CVE-2016-7489 poderiam ter sido evitadas se essa feature existisse em suas respectivas épocas, [como apontado pelo Linus Torvalds no commit que introduziu essa opção](https://github.com/torvalds/linux/commit/30aba6656f).

### `kernel.sysrq = 0`
Esse parâmetro desativa totalmente a feature "SysRq Magic Key" que raramente é útil e pode representar um vetor de ataque em certos casos.
[Veja mais detalhes na respectiva página sobre isso no projeto Debian.](https://www.debian.org/doc/manuals/securing-debian-manual/restrict-sysrq.it.html)

### `net.ipv4.tcp_sack = 0`
Desabilita o TCP SACK, que é comumente vulnerável (CVE-2019-11477, por exemplo) e raramente útil, então deve ser desabilitado desde que não necessites explicitamente. [Veja mais detalhes](https://serverfault.com/questions/10955/when-to-turn-tcp-sack-off). 

<div id='sysdsndb'/>  

# Sandboxing de serviços com systemd sandboxes
**PENDENTE**

<div id='blacklists'/>  

# Attack surface reduzida pelo blacklisting de certos módulos
É possível efetuar a desativação forçada de certos módulos ativos do kernel ao impedir o carregamento deles através de blacklists em /etc/modprobe.d/. Listarei abaixo algumas dessas questões com suas respectivas explicações.

**/etc/modprobe.d/blacklist-bluetooth.conf**
```
# Impede que módulos do kernel relacionados a Bluetooth sejam carregados, isso quebra qualquer possibilidade de usá-lo, o que me é irrelevante.
install bluetooth /bin/true
install btusb /bin/true
```

**/etc/modprobe.d/blacklist-mei.conf**
```
# Impede que o módulo mei seja carregado. Ele é a 'interface' entre o sistema e o Intel ME.
# LEMBRANDO QUE ISSO **NÃO** DESATIVA E NEM REMOVE O INTEL ME, o INTEL ME É ALGO BEM MAIS PROFUNDO QUE ISSO, ALÉM DA TUTELA DE QUALQUER SISTEMA OPERACIONAL.
install mei-me /bin/true
install mei /bin/true
```

Dúvida comum: "Por que `install nomeModulo /bin/true` nos arquivos acima?"

Eu poderia usar `blacklist nomedomodulo`, mas se algum outro módulo dependesse do módulo 'proibido', o blacklist seria ignorado, portanto optei por forçar usando `install nomedomodulo /bin/true`, que é um workaround que fará com que o modprobe rode /bin/true (nenhum motivo para esse executável em específico) em vez de carregar o módulo.

<div id='sandboxingextra'/>  

# Confinamento de programas específicos
o Bubblewrap é um programa adicional para executar outros programas em sandbox, suas sandboxes são possibilitadas por Linux namespaces, seccomp e Linux capabilites, possibilitando assim que os programas executados através dele rodem em processos restritos por seccomp e Linux capabilities e isolados do resto com Linux namespaces.

É possível criar e usar profiles do AppArmor para restringir e controlar o acesso de diversos programas.

Como alternativa ao Bubblewarp, existe o Firejail, [mas o Firejail é dito como tendo uma superfície de ataque maior, inclusive tendo possibilitado escalação de privilégios no passado.](https://github.com/netblue30/firejail/issues/3046)

## Bubblewrap
Este parágrafo lhe introduzirá o uso do Bubblewrap a fim de confinar determinados programas através de Linux namespaces e restringi-los através de Linux capabilities e seccomp.

o Bubblewrap é útil como uma medida adicional de isolamento e restrição a programas, como navegadores e programas de chat, que são diariamente expostos à interação com conteúdos externos, **mesmo que os navegadores de hoje tenham seus próprios mecanismos de sandboxing que são extremamente seguros e serão abordados abaixo no tópico [sobre navegadores](#javascriptsucks).**


**PENDENTE**
## AppArmor
Abaixo você pode ver uma introdução à criação e ao uso de profiles AppArmor para a execução de determinados programas:

**PENDENTE**

<div id='luks'/>  

# LUKS e criptografia negável
LUKS é uma solução extremamente poderosa para full disk encryption dos dados em repouso, qualquer setup hardened de Linux deveria contar com um uso apropriado do LUKS, esta parte do guia visa evidenciar algo que poucos conhecem e que pode ser implementado em um setup LUKS: Criptografia negável.

Um cenário onde o header das partições LUKS é residente em um dispositivo externo e não no disco rígido é favorável à criptografia negável e plausible deniability, onde o usuário teria como alegar que os dados do disco rígido não estão criptografados, pois o header do LUKS estaria em um dispositivo fisicamente externo. Ao implementar isso, os dados criptografados no disco seriam simplesmente dados brutos, aleatórios e ilegíveis, pois não haverá no disco a figura da estrutura centralizada que é o header LUKS. Note que se você fizer isso e perder esse dispositivo externo, não será mais possível acessar os dados do computador, pois o header LUKS contém toda a parte lógica, os metadados e chaves criptográficas do LUKS, já que nesse cenário o disco rígido armazena apenas os dados brutos criptografados.

Um fato interessante é que isso, naturalmente, adiciona um novo fator de proteção à criptografia do LUKS, já que será necessário ter o dispositivo externo que contém o header para poder ao menos digitar a senha para acessar os dados. 


Por último, costumo fortificar um pouco o comando `cryptsetup` usado para criptografar o disco com LUKS. Veja detalhes:

* Hoje, o padrão do *cryptsetup* ao executar o comando sem argumentos específicos (`cryptsetup -v luksFormat /dev/nvme0n1p2`) seria:
    * `cryptsetup -v --type luks2 --cipher aes-xts-plain64 --key-size 256 --hash sha256 --iter-time 2000 --use-urandom --verify-passphrase luksFormat /dev/nvme0n1p2`

* O que eu faço é rodar o comando base, alterando apenas o algoritmo de hash do padrão SHA256 para SHA512 e aumentando o `--iter-time` de 2 para 5 segundos. Confira:
    * `cryptsetup -v --hash sha512 --iter-time 5000 --use-urandom --verify-passphrase luksFormat /dev/nvme0n1p2`

<div id='integridadeboot'/>  

# Detached /boot e Secure Boot
Combinado com o tópico anterior, é interessante fazer o que chamam de *detached boot partition*, o uso da partição de boot estando em um dispositivo externo, o que impossibilitará que o sistema operacional seja iniciado sem esse dispositivo externo conectado, é interessante que o setup use LUKS e que o header do LUKS também fique externado neste dispositivo.

Se o seu computador tiver uma placa-mãe lançada nos últimos 10 anos, é bem provável que ela tenha um firmware UEFI que suporta Secure Boot, podes usar o Secure Boot a seu favor para impedir a inicialização de imagens que alguém pode ter adulterado do bootloader, do kernel e/ou do initramfs que ficam na sua partição de boot. O Secure Boot exigirá que qualquer código a ser inicializado pelo computador esteja assinado com uma assinatura confiável, as imagens do seu bootloader, kernel e initramfs deverão ser assinadas com uma chave confiável que também deve ser configurada no Secure Boot na BIOS.

<div id='minimalismo'/>  

# Attack surface reduzida pelo minimalismo
Usar softwares com menos dependências e uma base de código pequena é uma boa prática, uma base de código pequena é muito mais fácil de manter e mais difícil de introduzir erros. Manter o Arch Linux com o menor número de pacotes possível também é uma boa prática nesse aspecto.

Um exemplo disso é a 'interface' de usuário que uso no meu setup, o dwm, um gerenciador de janelas para o X11 que, sem patches adicionais, não tem mais de 3500 linhas de código e basicamente depende apenas do Xorg. Como o próprio nome diz, o dwm **não** é um Desktop Environment, ele é apenas um Window Manager, eu o utilizo, pessoalmente, por me sentir mais produtivo nele, já que é uma experiência mais voltada a teclado e keybindings, com alteração rápida entre workspaces, uma statusbar customizável, posicionamento eficaz de janelas e muito mais, tudo isso em menos de 3500 linhas de código.

<div id='javascriptsucks'/>  

# Navegador web
Navegadores são pontos importantes na segurança do computador, já que eles estão diariamente expostos a conteúdos externos na internet, eles interpretam código JavaScript, executam diversos tipos de arquivos, desde PDFs, imagens, áudios, HTML e vídeos até conteúdos em WebGL. Os navegadores costumam rodar em processos isolados e com mecanismos de sandboxing que funcionam através de capacidades do kernel Linux, fazem uso do seccomp-bpf, Yama, Linux namespaces, isso impede que, caso o navegador seja comprometido por uma vulnerabilidade, o resto do sistema **não** seja afetado. 

Portanto, precisamos escolher um navegador seguro, mas também precisamos ter privacidade, algo que nem todo navegador possibilita.

Vale ressaltar que eu, pessoalmente, **uso o Chromium** **(ou, para mais privacidade, o [ungoogled-chromium](https://github.com/Eloston/ungoogled-chromium) em setups onde estou disposto a perder horas compilando-o)** e desativo o JavaScript nas configurações do meu navegador e adiciono exceções apenas para uma extensa lista de sites em que confio ou que preciso usar e exijam JavaScript. Uso a extensão uBlock Origin para bloqueio de ads, trackers e conteúdo malicioso e a extensão HTTPS Everywhere forçando HTTPS onde possível e rejeitando conexões HTTP.

As escolhas mais aconselháveis são Chromium ou Firefox, pessoalmente, a minha escolha é o Chromium, pelos motivos que citarei abaixo. **Apesar disso, considero o Firefox como um melhor respeitador da privacidade do usuário, além de ser mais customizável.** Abaixo listarei os motivos de segurança que causaram a minha escolha do Chromium:

* O Firefox ainda não conta com a feature de [Site Isolation](https://www.chromium.org/developers/design-documents/site-isolation), que faria com que CADA SITE fosse executado em sua sandbox separada da sandbox principal do navegador. A Mozilla está trabalhando no [Project Fission](https://wiki.mozilla.org/Project_Fission), que é a feature de Site Isolation que chegará ao Firefox em 2021, enquanto o [Chromium apresenta Site Isolation desde 2018](https://security.googleblog.com/2018/07/mitigating-spectre-with-site-isolation.html).

* [O Firefox apresenta vulnerabilidades ainda não corrigidas e datadas de 6 anos em relação ao X11 que hoje podem causar sandbox escape (link)](https://bugzilla.mozilla.org/show_bug.cgi?id=1129492). Isso ocorre porque [o X11 não tem GUI Isolation](https://theinvisiblethings.blogspot.com/2011/04/linux-security-circus-on-gui-isolation.html). O Chromium mitiga isso expondo o X11 apenas ao processo sandboxeado da GPU, o processo do renderer (onde os sites são executados) não tem acesso. Esse problema facilitaria um sandbox escape, como é possível ver em um caso parecido [aqui](https://mjg59.dreamwidth.org/42320.html).

* No Firefox, o processo da GPU não é protegido pelo mecanismo de sandbox, o que é feito no Chromium, como é possível verificar em chrome://gpu. Enquanto isso no Firefox, segundo a própria `wiki.mozilla.org`: "[To-do. Not sandboxed currently. Only present on Windows, but will likely be added to OS X and Linux with Web Render. Implemented in bug 1347710 but waiting on VR process work.](https://wiki.mozilla.org/Security/Sandbox/Process_model#GPU_Process)"

* O Firefox ainda usa o mozjemalloc como alocador de memória, que é um fork do jemalloc, que por sua vez é inseguro, como mostra [esse artigo da BlackHat](https://media.blackhat.com/bh-us-12/Briefings/Argyoudis/BH_US_12_Argyroudis_Exploiting_the_%20jemalloc_Memory_%20Allocator_Slides.pdf). A Mozilla de fato fez seu fork ser mais seguro, [mas não o suficiente](https://lists.torproject.org/pipermail/tor-dev/2019-August/013990.html). Enquanto o Chromium usa o [PartitionAlloc](https://chromium.googlesource.com/chromium/src/+/master/base/allocator/partition_allocator/PartitionAlloc.md) que [é muito mais seguro que o mozjemalloc](https://struct.github.io/partition_alloc.html).

* [A Mozilla ainda não implementou CFI (Control-Flow Integrity)](https://bugzilla.mozilla.org/show_bug.cgi?id=510629) no Firefox, [por outro lado, o Chromium](https://www.chromium.org/developers/testing/control-flow-integrity) pode ser compilado [se beneficiando do CFI forward-edge do compilador clang](https://www.chromium.org/developers/testing/control-flow-integrity) para assim mitigar vários tipos de possíveis falhas de segurança e amenizar impactos.

* [Um artigo feito por um pesquisador de segurança ressalta que o compilador JIT que o Chromium usa em suas interpretações, é superior ao do Firefox](https://github.com/struct/research/blob/master/Attacking_Clientside_JIT_Compilers_Paper.pdf)

Com as informações acima e o [resumo oficial de features de segurança do Chromium](https://www.chromium.org/Home/chromium-security/brag-sheet) é possível concluir que ele é mais seguro que o Firefox em sua arquitetura e nas mitigações de segurança que propõe, além do Chromium ser um navegador mais robusto, moderno e suportado do que o Firefox, **apesar de o Firefox ser um bom defensor da privacidade e esse ser um grande ponto para ele.**

<div id='opensslsucks'/>  

# LibreSSL
Desde a Heartbleed, descoberta em 2014, o LibreSSL surge como uma alternativa mais segura e com um código mais limpo ao OpenSSL, é interessante realizar a troca.

Para isso, instale o LibreSSL com `sudo pacman -Sy libressl`, mas isso não basta, os pacotes oficiais do Arch Linux não são compilados para usar o LibreSSL, então ficaria a seu critério a devida recompilação dos pacotes com quais quiser usar o LibreSSL.

<div id='mallocopenbsd'/>  

# hardened_malloc, port do malloc do OpenBSD
Esta é uma reimplementação, uma substituição, do malloc() implementado pela glibc. O hardened_malloc é um port do alocador de memória do OpenBSD, port inicialmente desenvolvido pelo pesquisador de segurança Daniel Micay especificamente para a libc Bionic do Android e a libc musl, mas também disponível para o Arch Linux através de duas opções de pacote no AUR: [hardened_malloc](https://aur.archlinux.org/packages/hardened_malloc/) e [hardened-malloc-git](https://aur.archlinux.org/packages/hardened_malloc/).

Após instalar, adicione `LD_PRELOAD="/usr/lib/libhardened_malloc.so"` no comando, antes do nome de um programa que queiras executar com o hardened_malloc.

<div id='ucode'/>  

# Atualização do microcode
Você pode (e é recomendável) carregar o microcode da fabricante do processador [através do sistema operacional](https://wiki.archlinux.org/index.php/microcode), basta instalar o pacote `intel-ucode` ou `amd-ucode` e incluir nas configurações do seu bootloader o caminho para a imagem. Se não fizer isso, o microcode será carregado da BIOS, que muito provavelmente possui uma versão antiga do microcode.

<div id='rede'/>

# Rede local
Aqui vai um tópico que talvez não seja útil para todos, pois o setup de rede varia de acordo com o provedor e diversos outros fatores.

Anteriormente, eu operava com um modem Mitrastar da Vivo conectado ao meu roteador pessoal via modo bridge, mas decidi minimizar ainda mais o setup, pois queria substituir o modem da Vivo por algo menor, com uma superfície de ataque reduzida, foi aí que optei por comprar um terminal GPON da TP-LINK, um TP-LINK GX6610, um aparelho que em nenhum momento é conectado à internet, pois a autenticação PPPoE é feita apenas no roteador e não nele, ele simplesmente recebe o cabo de fibra da Vivo, faz os procedimentos GPON e é conectado por um cabo Ethernet ao meu roteador, meu roteador executa **OpenWRT**. Se fossemos desenhar um fluxograma, o primeiro dispositivo da minha rede a ter, de fato, conexão à internet, seria o roteador, já que como mencionei antes, é ele quem faz a autenticação PPPoE.

Falar sobre meu setup de rede talvez fosse necessitar de uma documentação específica, já que o OpenWRT que executo em meu roteador tem algumas questões profundas de hardening, pois compilo o OpenWRT por conta própria a fim de mantê-lo mínimo e atualizado, além de seguir as documentações oficiais de hardening do OpenWRT na compilação. Abaixo, links oficiais úteis sobre hardening em OpenWRT:

* https://openwrt.org/docs/guide-developer/security
* https://openwrt.org/docs/guide-user/security/openwrt_security
* https://openwrt.org/docs/guide-user/security/security-features

*Pretendo, no futuro, escrever sobre o meu setup do OpenWRT em outro arquivo neste mesmo repositório.*
