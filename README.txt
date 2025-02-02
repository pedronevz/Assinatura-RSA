Como utilizar:

Existem 3 tipos de modo de execução:
 
"-c": Gerar chaves
"-a": Assinar mensagem
"-v": Verificar assinatura

-------------------------------------------------------------------------------------------------------------
Gerar chaves:

Nesse modo o programa irá gerar 2 arquivos de texto contendo as chaves pública e privada.

python .\gerador_verificador_assinaturas.py -c

-------------------------------------------------------------------------------------------------------------
Assinar mensagem:

Além do argumento "-a" também devem ser passados a mensagem e a chave privada
tanto a chave quanto a mensagem podem ser passadas diretamente ou através de um arquivo de texto, o arquivo gerado pelo gerador de chaves funciona como um arquivo de chave
A execução nesse modo irá gerar um arquivo de texto chamado "assinatura.txt" contendo a assinatura em formato base64

python .\gerador_verificador_assinaturas.py -a .\minha_mensagem.txt .\chave_privada.txt

-------------------------------------------------------------------------------------------------------------
Verificar assinatura:

Além do argumento "-v" também devem ser passados a mensagem, a chave publica e a assinatura
A chave, mensagem e assinatura podem ser passados diretamente ou através de um arquivo de texto, o arquivo gerado pelo gerador de chaves funciona como um arquivo de chave

python .\gerador_verificador_assinaturas.py -v .\minha_mensagem.txt .\chave_publica.txt .\assinatura.txt