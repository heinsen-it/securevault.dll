library SecureVault;

{$R *.res}

uses
  System.SysUtils,
  System.Classes,
  IdHashMessageDigest,
  IdGlobal,
  IdCoderMIME,
  IdHMAC,
  IdHMACMD5,
  IdHMACSHA1,
  IdSSLOpenSSL,
  IdCTypes,
  u_securevault in 'u_securevault.pas';

type
  // Verschlüsselungsalgorithmen
  TEncryptionAlgorithm = (eaAES128, eaAES192, eaAES256, eaRSA1024, eaRSA2048, eaRSA4096);


    // Verschlüsselungsmodus
  TEncryptionMode = (emECB, emCBC, emCTR, emGCM);


   // Returnwert für diverse Funktionen
    TCardinalArray = array of Cardinal;


  // Fehlertypen
  TSecureVaultError = (
    sve_Success,
    sve_InvalidParameter,
    sve_InvalidKey,
    sve_InvalidData,
    sve_FileNotFound,
    sve_MemoryError,
    sve_CryptoError,
    sve_UnknownError
  );


   // AES-Implementierung
   // RFC 3826
   // https://datatracker.ietf.org/doc/html/rfc3826
  TAES = class
  private
    FKey: array[0..31] of Byte;
    FRoundKeys: array[0..59] of Cardinal;
    FKeyLength: Integer;
    FRounds: Integer;

    procedure KeyExpansion;

        function ShiftRows(State: array of Cardinal): TCardinalArray;
    function SubBytes(State: Cardinal): Cardinal;
    function InvSubBytes(State: Cardinal): Cardinal;

      public
      constructor Create(const Key: array of Byte; KeyLength: Integer);

     end;

    // RSA-Implementierung
  TRSA = class
   private

   public

  end;



begin


procedure SetError(Context: PSecureVaultContext; Error: TSecureVaultError; const Message: string);
begin
  if Context <> nil then
  begin
    Context.LastError := Error;
    System.AnsiStrings.StrPCopy(Context.ErrorMessage, AnsiString(Message));
  end;
end;

// AES-Implementierung
// Why Error ?!?!
constructor TAES.Create(const Key: array of Byte; KeyLength: Integer);
var
  I: Integer;
begin
  inherited Create;
  FKeyLength := KeyLength;

  for I := 0 to KeyLength - 1 do
    FKey[I] := Key[I];

  case KeyLength of
    16: FRounds := 10; // AES-128
    24: FRounds := 12; // AES-192
    32: FRounds := 14; // AES-256
  end;

  KeyExpansion;

end;

//https://en.wikipedia.org/wiki/AES_key_schedule#Rcon
//https://crypto.stackexchange.com/questions/2418/how-to-use-rcon-in-key-expansion-of-128-bit-advanced-encryption-standard
procedure TAES.KeyExpansion;
var
  I, J: Integer;
  Temp: Cardinal;
 const Rcon: array[0..9] of Cardinal = ($01000000, $02000000, $04000000, $08000000,
                                   $10000000, $20000000, $40000000, $80000000,
                                   $1B000000, $36000000);
begin
  // Erste Runde-Schlüssel aus dem ursprünglichen Schlüssel kopieren
  for I := 0 to (FKeyLength div 4) - 1 do
    FRoundKeys[I] := PCardinal(@FKey[I * 4])^;

  // Weitere Runde-Schlüssel generieren
  for I := FKeyLength div 4 to (FRounds + 1) * 4 - 1 do
  begin
    Temp := FRoundKeys[I - 1];

    if (I mod (FKeyLength div 4)) = 0 then
    begin
      Temp := SubBytes(((Temp shl 8) or (Temp shr 24))) xor Rcon[(I div (FKeyLength div 4)) - 1];
    end
    else if (FKeyLength = 32) and ((I mod 8) = 4) then
    begin
      Temp := SubBytes(Temp);
    end;

    FRoundKeys[I] := FRoundKeys[I - (FKeyLength div 4)] xor Temp;
  end;
end;

// https://asecuritysite.com/subjects/chapter88
function TAES.SubBytes(State: Cardinal): Cardinal;
const
  SBox: array[0..255] of Byte = (
    $63, $7C, $77, $7B, $F2, $6B, $6F, $C5, $30, $01, $67, $2B, $FE, $D7, $AB, $76,
    $CA, $82, $C9, $7D, $FA, $59, $47, $F0, $AD, $D4, $A2, $AF, $9C, $A4, $72, $C0,
    $B7, $FD, $93, $26, $36, $3F, $F7, $CC, $34, $A5, $E5, $F1, $71, $D8, $31, $15,
    $04, $C7, $23, $C3, $18, $96, $05, $9A, $07, $12, $80, $E2, $EB, $27, $B2, $75,
    $09, $83, $2C, $1A, $1B, $6E, $5A, $A0, $52, $3B, $D6, $B3, $29, $E3, $2F, $84,
    $53, $D1, $00, $ED, $20, $FC, $B1, $5B, $6A, $CB, $BE, $39, $4A, $4C, $58, $CF,
    $D0, $EF, $AA, $FB, $43, $4D, $33, $85, $45, $F9, $02, $7F, $50, $3C, $9F, $A8,
    $51, $A3, $40, $8F, $92, $9D, $38, $F5, $BC, $B6, $DA, $21, $10, $FF, $F3, $D2,
    $CD, $0C, $13, $EC, $5F, $97, $44, $17, $C4, $A7, $7E, $3D, $64, $5D, $19, $73,
    $60, $81, $4F, $DC, $22, $2A, $90, $88, $46, $EE, $B8, $14, $DE, $5E, $0B, $DB,
    $E0, $32, $3A, $0A, $49, $06, $24, $5C, $C2, $D3, $AC, $62, $91, $95, $E4, $79,
    $E7, $C8, $37, $6D, $8D, $D5, $4E, $A9, $6C, $56, $F4, $EA, $65, $7A, $AE, $08,
    $BA, $78, $25, $2E, $1C, $A6, $B4, $C6, $E8, $DD, $74, $1F, $4B, $BD, $8B, $8A,
    $70, $3E, $B5, $66, $48, $03, $F6, $0E, $61, $35, $57, $B9, $86, $C1, $1D, $9E,
    $E1, $F8, $98, $11, $69, $D9, $8E, $94, $9B, $1E, $87, $E9, $CE, $55, $28, $DF,
    $8C, $A1, $89, $0D, $BF, $E6, $42, $68, $41, $99, $2D, $0F, $B0, $54, $BB, $16
  );
var
  I: Integer;
  Bytes: array[0..3] of Byte;
begin
  PCardinal(@Bytes)^ := State;
  for I := 0 to 3 do
    Bytes[I] := SBox[Bytes[I]];
  Result := PCardinal(@Bytes)^;
end;



function TAES.InvSubBytes(State: Cardinal): Cardinal;
const
  InvSBox: array[0..255] of Byte = (
    $52, $09, $6A, $D5, $30, $36, $A5, $38, $BF, $40, $A3, $9E, $81, $F3, $D7, $FB,
    $7C, $E3, $39, $82, $9B, $2F, $FF, $87, $34, $8E, $43, $44, $C4, $DE, $E9, $CB,
    $54, $7B, $94, $32, $A6, $C2, $23, $3D, $EE, $4C, $95, $0B, $42, $FA, $C3, $4E,
    $08, $2E, $A1, $66, $28, $D9, $24, $B2, $76, $5B, $A2, $49, $6D, $8B, $D1, $25,
    $72, $F8, $F6, $64, $86, $68, $98, $16, $D4, $A4, $5C, $CC, $5D, $65, $B6, $92,
    $6C, $70, $48, $50, $FD, $ED, $B9, $DA, $5E, $15, $46, $57, $A7, $8D, $9D, $84,
    $90, $D8, $AB, $00, $8C, $BC, $D3, $0A, $F7, $E4, $58, $05, $B8, $B3, $45, $06,
    $D0, $2C, $1E, $8F, $CA, $3F, $0F, $02, $C1, $AF, $BD, $03, $01, $13, $8A, $6B,
    $3A, $91, $11, $41, $4F, $67, $DC, $EA, $97, $F2, $CF, $CE, $F0, $B4, $E6, $73,
    $96, $AC, $74, $22, $E7, $AD, $35, $85, $E2, $F9, $37, $E8, $1C, $75, $DF, $6E,
    $47, $F1, $1A, $71, $1D, $29, $C5, $89, $6F, $B7, $62, $0E, $AA, $18, $BE, $1B,
    $FC, $56, $3E, $4B, $C6, $D2, $79, $20, $9A, $DB, $C0, $FE, $78, $CD, $5A, $F4,
    $1F, $DD, $A8, $33, $88, $07, $C7, $31, $B1, $12, $10, $59, $27, $80, $EC, $5F,
    $60, $51, $7F, $A9, $19, $B5, $4A, $0D, $2D, $E5, $7A, $9F, $93, $C9, $9C, $EF,
    $A0, $E0, $3B, $4D, $AE, $2A, $F5, $B0, $C8, $EB, $BB, $3C, $83, $53, $99, $61,
    $17, $2B, $04, $7E, $BA, $77, $D6, $26, $E1, $69, $14, $63, $55, $21, $0C, $7D
  );
var
  I: Integer;
  Bytes: array[0..3] of Byte;
begin
  PCardinal(@Bytes)^ := State;
  for I := 0 to 3 do
    Bytes[I] := InvSBox[Bytes[I]];
  Result := PCardinal(@Bytes)^;
end;


function TAES.ShiftRows(State: array of Cardinal): TCardinalArray;
var
  Temp: array[0..15] of Byte;
  I: Integer;
begin
  // State zu Bytes konvertieren
  for I := 0 to 3 do
    PCardinal(@Temp[I * 4])^ := State[I];

  // Zeilen verschieben
  Result[0] := (Cardinal(Temp[0]) shl 24) or (Cardinal(Temp[5]) shl 16) or (Cardinal(Temp[10]) shl 8) or Cardinal(Temp[15]);
  Result[1] := (Cardinal(Temp[4]) shl 24) or (Cardinal(Temp[9]) shl 16) or (Cardinal(Temp[14]) shl 8) or Cardinal(Temp[3]);
  Result[2] := (Cardinal(Temp[8]) shl 24) or (Cardinal(Temp[13]) shl 16) or (Cardinal(Temp[2]) shl 8) or Cardinal(Temp[7]);
  Result[3] := (Cardinal(Temp[12]) shl 24) or (Cardinal(Temp[1]) shl 16) or (Cardinal(Temp[6]) shl 8) or Cardinal(Temp[11]);
end;


end.
