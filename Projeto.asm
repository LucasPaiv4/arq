; Lucas Paiva de Araújo

.686
.model flat, stdcall
option casemap:none

include \masm32\include\windows.inc
include \masm32\include\masm32.inc
include \masm32\include\kernel32.inc
includelib \masm32\lib\masm32.lib
includelib \masm32\lib\kernel32.lib

.data
    ; Strings do menu e prompts
    menuTitle       db "Cifra de Cesar",13,10,0
    option1         db "1. Descriptografar",13,10,0
    option2         db "2. Criptografar",13,10,0
    option3         db "3. Criptoanalise",13,10,0
    option4         db "4. Sair",13,10,0
    menuPrompt      db "Escolha uma opcao:",0

    filePrompt      db "Digite o nome do arquivo de entrada:",0
    outFilePrompt   db "Digite o nome do arquivo de saida:",0
    keyPrompt       db "Digite a chave (1 a 20):",0
    
    ; Buffers e variáveis auxiliares
    inputFileBuffer  db 512 dup(0)
    outputFileBuffer db 512 dup(0)
    userInputBuffer db 256 dup(0)
    buffer          db 512 dup(0)
    keyBuffer       db 256 dup(0)
    console_count   dd 0
    inputHandle     dd 0
    outputHandle    dd 0
    bytesRead       dd 0
    bytesWritten    dd 0    

.code
start:
    ; Obtém os handles de entrada e saída padrão
    invoke GetStdHandle, STD_INPUT_HANDLE
    mov inputHandle, eax

    invoke GetStdHandle, STD_OUTPUT_HANDLE
    mov outputHandle, eax
    

menuLoop:
    ; Exibe o menu de opções e lê a escolha do usuário
    invoke WriteConsole, outputHandle, addr menuTitle, sizeof menuTitle, addr console_count, NULL
    invoke WriteConsole, outputHandle, addr option1, sizeof option1, addr console_count, NULL
    invoke WriteConsole, outputHandle, addr option2, sizeof option2, addr console_count, NULL
    invoke WriteConsole, outputHandle, addr option3, sizeof option3, addr console_count, NULL
    invoke WriteConsole, outputHandle, addr option4, sizeof option4, addr console_count, NULL
    invoke WriteConsole, outputHandle, addr menuPrompt, sizeof menuPrompt, addr console_count, NULL
    invoke ReadConsole, inputHandle, addr userInputBuffer, sizeof userInputBuffer, addr console_count, NULL

    ; Verifica a opção escolhida e executa a ação correspondente
    mov al, byte ptr [userInputBuffer]
    cmp al, '4'
    je exitProgram

    cmp al, '1'
    je descriptografar
    cmp al, '2'
    je criptografar
    cmp al, '3'
    je criptoanalise

    jmp menuLoop

descriptografar:
    ; Solicita e lê os nomes dos arquivos de entrada, saída e chave
    invoke StdOut, addr filePrompt
    invoke StdIn, addr inputFileBuffer, 512

    invoke StdOut, addr outFilePrompt
    invoke StdIn, addr outputFileBuffer, 512

    invoke StdOut, addr keyPrompt
    invoke StdIn, addr keyBuffer, 256

    invoke atodw, addr keyBuffer    ; Converte a chave de string para valor numérico
    mov byte ptr [keyBuffer], al

    invoke CreateFile, addr inputFileBuffer, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL
    mov edi, eax

    invoke CreateFile, addr outputFileBuffer, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL
    mov ebx, eax

    ; Inicia o loop de Leitura
    @@readLoop1:
        invoke ReadFile, edi, addr buffer, sizeof buffer, addr bytesRead, NULL  ; Lê um bloco de 512 bytes do arquivo de entrada e armazena no buffer
        xor ecx, ecx        
        mov ecx, dword ptr [bytesRead]      
        cmp ecx, 0          ; Verifica se nenhum byte foi lido, se sim o loop é encerrado
        je @@endReadLoop1

        lea ebp, [buffer]    ; Carrega o endereço efetivo do buffer no registrador EBP
        mov esi, ebp
        mov edx, ecx

        ; Inicia o loop de descriptografia
        @@loop1:  
            mov al, byte ptr [esi]      ; Carrega o byte atual do buffer no registrador AL
            sub al, byte ptr [keyBuffer]        ; Subtrai o valor da chave do byte atual para descriptografar
            mov byte ptr [ebp], al      ; Armazena o resultado de volta no buffer

            ; Atualizam os registradores para apontar para o próximo byte no buffer
            inc esi
            inc ebp
            dec edx
            jnz @@loop1     ; Verifica se ainda restam bytes para processar


        ; Atualiza o valor de ecx para o número correto de bytes lidos
        mov ecx, dword ptr [bytesRead]

        invoke WriteFile, ebx, addr buffer, ecx, addr bytesWritten, NULL
        cmp ecx, sizeof buffer

        jmp @@readLoop1
    @@endReadLoop1:
    invoke CloseHandle, edi
    invoke CloseHandle, ebx

    jmp menuLoop

criptografar:
    ; Solicita e lê os nomes dos arquivos de entrada, saída e chave
    invoke StdOut, addr filePrompt
    invoke StdIn, addr inputFileBuffer, 512

    invoke StdOut, addr outFilePrompt
    invoke StdIn, addr outputFileBuffer, 512

    invoke StdOut, addr keyPrompt
    invoke StdIn, addr keyBuffer, 256

    invoke atodw, addr keyBuffer      ; Converte a chave de string para valor numérico       
    mov byte ptr [keyBuffer], al

    invoke CreateFile, addr inputFileBuffer, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL

    mov edi, eax

    invoke CreateFile, addr outputFileBuffer, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL

    mov ebx, eax

    ; Inicia o loop de Leitura
    @@readLoop2:
        invoke ReadFile, edi, addr buffer, sizeof buffer, addr bytesRead, NULL   ; Lê um bloco de 512 bytes do arquivo
        xor ecx, ecx
        mov ecx, dword ptr [bytesRead]
        cmp ecx, 0          ; Verifica se nenhum byte foi lido, se sim o loop é encerrado
        je @@endReadLoop2

        lea ebp, [buffer]       ; Carrega o endereço efetivo do buffer no registrador EBP
        mov esi, ebp
        mov edx, ecx            

        ; Inicia o loop de criptografia
        @@loop2:
            mov al, byte ptr [esi]          ; Carrega o byte atual do buffer no registrador AL
            add al, byte ptr [keyBuffer]    ; Adiciona o valor da chave do byte atual para descriptografar
            mov byte ptr [ebp], al          ; Armazena o resultado de volta no buffer

            ; Atualizam os registradores para apontar para o próximo byte no buffer
            inc esi
            inc ebp
            dec edx
            jnz @@loop2      ; Verifica se ainda restam bytes para processar


        ; Atualiza o valor de ecx para o número correto de bytes lidos
        mov ecx, dword ptr [bytesRead]

        invoke WriteFile, ebx, addr buffer, ecx, addr bytesWritten, NULL
        cmp ecx, sizeof buffer

        jmp @@readLoop2
    @@endReadLoop2:

    invoke CloseHandle, edi
    invoke CloseHandle, ebx

    jmp menuLoop

criptoanalise:
    invoke StdOut, addr filePrompt
    invoke StdIn, addr inputFileBuffer, 256

    jmp menuLoop

exitProgram:
    invoke ExitProcess, 0

end start