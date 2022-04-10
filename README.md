# PROXYING DLL LIBRARY

A técnica de proxificar DLLs do Windows, seja para persistência no sistema ou para hooking de funções é antiga, e diversos artigos explicam a fundo a técnica, de um modo muito melhor e mais completo do que poderiamos fazer.

Existem atualmente diversas ferramentas que buscam facilitar o procedimento de proxificar DLLs disponiveis na internet, mas todas as pesquisadas criam um arquivo DEF (ou similar) que deve ser compilado junto com o código fonte da DLL substituta para criar os _Exports Forwards_ que apontarão para a DLL original. 

Essa criação estática dos _Export Forwards_ acaba por engessar o usuário, uma vez que limitam sobre quais DLLs o proxy poderá ser aplicado para o momento da compilação, na máquina do atacante, impedindo a adaptação dinamica a situação real, encontrada na máquina sob ataque.

Mas isso não obrigatoriamente deveria ser assim. Tanto o formato dos arquivos PE quanto do formato das tabelas e ponteiros de seus _Exports_ é conhecido, e já foi muito estudado. Criar os _Exports Forwards_ não necessariamente deveria ser feito pelo compilador.

Por isso, apresentamos aqui nossa ferramenta, juntamente com um biblioteca (_header-only_).

Alimentado com dois nomes de arquivos DLLs, uma com o código do atacante, e a outra sendo a DLL a ser atacada, ela analisa todos os _exports_, reconstroi as estruturas que os definem, e retorna o resultado em um novo arquivo.

A DLL atacante deverá apenas definir em seu DllMain() o código que deseja ver executado quando da carga em memoria, e implementar (como _export_), apenas as funções que deseja interceptar. A ferramenta modificará as estruturas de exportação, criando _Exports Forwards_ para todas as funções não interceptadas, respeitando os _Export Forwards_ já existente, e reutilizando a seção de _exports_ já existente (mais discreto contra analises forenses), ou criando uma nova seção com tais informações (quando não há espaço na imagem para as novas estruturas de exportação).

Desse modo, o atacante não necessita se preocupar com versões, funções que não deseja interceptar, nem precisa se preparar de antemão para possiveis variações se seus alvos.

## A FERRAMENTA PROXIFY

A ferramenta apresentada, que nada mais é que uma embalagem para a biblioteca (apresentada mais abaixo) que faz todo o trabalho, tem a seguinte sintaxe:

`proxify -i input.dll -o output.dll -m malware.dll -d newinputname -s newexportsection -v`

Em `-i input.dll` colocamos o nome da DLL que vamos atacar, (por exemplo, `steam_ui.dll`). Em `-o output.dll`, colocamos onde queremos que o resultado seja escrito no disco, por exemplo, `temp.dll`. Em `-m malware.dll` colocamos a DLL que tem nosso código. Em `-d newinputname` se coloca o nome onde a DLL original será futuramente copiada (por exemplo, `steam_ui2.dll`). E, opcionalmente, em `-s newexportsection`, o nome da nova seção que criaremos no arquivo de saída caso não haja espaço na export table original, como, por exemplo `.exports` (se não é indicado um nome de seção, e não há espaço na seção original, o processamento falha).

A opção opcional `-v`, verbose, informa na tela informações sobre o processamento.

Depois da ferramenta terminar seu trabalho, devemos mover `input.dll` para `newinputname.dll`, e `output.dll` para `input.dll`.

## BIBLIOTECA

### PROXIFY_DLL()

A classe PDL tem apenas um membro público:

```
 proxify_dll()
   params->
     fake_dll        : mmap of our proxy dll
     original_dll    : mmap of dll to proxify
     dllname         : name of the dll to proxify (with ".DLL" ending)
     newdllname      : name we will rename the proxified dll (without ".DLL" ending)
     newsectionname  : name of new section
     flags:            PDL_FLAG_VERBOSE  -> show debug info
                       PDL_FLAG_REUSE    -> reuse existing export section
                       PDL_FLAG_CREATE   -> create new export section
   return->
                  : new size, or 0 if error
```

O mapa de memória pode ser criado com mmap(), CreateFile()/CreateFileMapping()/MapViewOfFile(), ou simplesmente ser um buffer com o conteúdo das DLLs. O parametro `fake_dll` deve ter espaço adicional se a flag `PDL_FLAG_CREATE` for usada.

## EXAMPLES

Na pasta EXEMPLOS, temos SIMPLES, que demonstra o caminho de execução de uma DLL proxificada, e em HOOK, temos um exemplo de gancho que intercepta uma função de validação de senha.

## LICENÇA DE USO

```
Copyright 2022 jmgk distributed under GNU LGPL version 3 or any later version
```
![LPGL3](https://www.gnu.org/graphics/lgplv3-with-text-154x68.png "LPGL3")
