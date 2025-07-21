unit u_securevault;



{
Interface Unit

Definiert Schnittstelle zur SecureVault.dll

}

interface

uses
  Winapi.Windows, System.SysUtils;

  const
  SECUREVAULT_DLL = 'SecureVault.dll';



type
  // Verschlüsselungsalgorithmen
  TEncryptionAlgorithm = (
    eaAES128 = 0,
    eaAES192 = 1,
    eaAES256 = 2,
    eaRSA1024 = 3,
    eaRSA2048 = 4,
    eaRSA4096 = 5
  );

  // Verschlüsselungsmodus
  TEncryptionMode = (
    emECB = 0,
    emCBC = 1,
    emCTR = 2,
    emGCM = 3
  );

  // Padding-Modus
  TPaddingMode = (
    pmPKCS7 = 0,
    pmZeros = 1,
    pmNone = 2
  );

  // Fehlertypen
  TSecureVaultError = (
    sve_Success = 0,
    sve_InvalidParameter = 1,
    sve_InvalidKey = 2,
    sve_InvalidData = 3,
    sve_FileNotFound = 4,
    sve_MemoryError = 5,
    sve_CryptoError = 6,
    sve_UnknownError = 7
  );

  // Funktionen der DLL
  function SV_CreateContext(Algorithm: TEncryptionAlgorithm; Mode: TEncryptionMode;
  Padding: TPaddingMode): Integer; stdcall; external SECUREVAULT_DLL;


  // Wrapper-Klasse für einfache Verwendung
type
  TSecureVault = class
  private
      FHandle: Integer;
    FAlgorithm: TEncryptionAlgorithm;
    FMode: TEncryptionMode;
    FPadding: TPaddingMode;

  public
      constructor Create(Algorithm: TEncryptionAlgorithm; Mode: TEncryptionMode = emCBC;
      Padding: TPaddingMode = pmPKCS7);

  end;


implementation

// Wrapper-Klasse Implementierung
constructor TSecureVault.Create(Algorithm: TEncryptionAlgorithm; Mode: TEncryptionMode;
  Padding: TPaddingMode);
begin
  inherited Create;
  FAlgorithm := Algorithm;
  FMode := Mode;
  FPadding := Padding;
  FHandle := SV_CreateContext(Algorithm, Mode, Padding);
  if FHandle = -1 then
    raise Exception.Create('Failed to create SecureVault context');
end;

end.
