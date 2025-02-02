Como utilizar:

Existem 3 tipos de modo de execução:
 
"1" => Gerar chaves
"2" => Assinar mensagem
"3" => Verificar assinatura

-------------------------------------------------------------------------------------------------------------
Gerar chaves:

Nesse modo, o programa irá gerar 2 arquivos de texto contendo as chaves pública e privada, chamados "chave_publica.txt" e "chave_privada.txt"
O arquivo gerado pelo gerador de chaves funciona como um arquivo de chave

-------------------------------------------------------------------------------------------------------------
Assinar mensagem:

"Digite o caminho do arquivo da mensagem: "
Deve ser passado o caminho do arquivo da mensagem no formato >> .\minha_mensagem.txt

"Digite o caminho do arquivo da chave privada: "
Deve ser passado o caminho do arquivo da chave_privada no formato >> .\chave_privada.txt

A execução nesse modo irá gerar um arquivo de texto chamado "assinatura.txt" contendo a assinatura em formato base64

-------------------------------------------------------------------------------------------------------------
Verificar assinatura:

Os inputs ocorrem da mesma maneira da assinatura. Devem ser passadas a mensagem, a chave publica e a assinatura