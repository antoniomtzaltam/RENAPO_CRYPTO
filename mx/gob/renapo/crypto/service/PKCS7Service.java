package mx.gob.renapo.crypto.service;

import java.io.File;
import mx.gob.renapo.crypto.exception.GenerarArchivoPKCS7Exception;

public interface PKCS7Service {
  byte[] generateFile(File paramFile1, String paramString, File paramFile2, File paramFile3) throws GenerarArchivoPKCS7Exception;
  
  boolean verifyKeystore(File paramFile, String paramString);
}


/* Location:              C:\Trabajo\P7M\PKCS7Generator.jar!\mx\gob\renapo\crypto\service\PKCS7Service.class
 * Java compiler version: 6 (50.0)
 * JD-Core Version:       1.1.3
 */