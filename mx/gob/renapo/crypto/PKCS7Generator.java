package mx.gob.renapo.crypto;

import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.Date;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;
import mx.gob.renapo.crypto.exception.GenerarArchivoPKCS7Exception;
import mx.gob.renapo.crypto.exception.IniciarAplicacionException;
import mx.gob.renapo.crypto.exception.ValidarDatosEntradaException;
import mx.gob.renapo.crypto.service.PKCS7Service;
import mx.gob.renapo.crypto.service.PKCS7ServiceImpl;
import org.apache.log4j.Logger;
import org.xml.sax.ErrorHandler;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import org.xml.sax.SAXParseException;
import org.xml.sax.XMLReader;

public class PKCS7Generator {
	private static Logger log = Logger.getLogger(PKCS7Generator.class);
	private File rutaNist;
	private File rutaKeystore;
	private String pin;
	private File rutaCertificadoFTP;
	private File rutaArchivoSalida;
	private String curpResponsable;
	private String noEquipo;
	private PKCS7Service pkcs7Service;

	public static void main(String[] args) {
		try {
			PKCS7Generator gen = new PKCS7Generator();
			gen.setPkcs7Service((PKCS7Service) new PKCS7ServiceImpl());
			gen.setRutaNist(args[0]);
			gen.setRutaKeystore(args[1]);
			gen.setPin(args[2]);
			gen.setRutaCertificadoFtp(args[3]);
			gen.setRutaArchivoSalida(args[4]);
			gen.setCurpResponsable(args[5]);
			gen.setNoEquipo(args[6]);

			byte[] file = gen.pkcs7Service.generateFile(gen.rutaKeystore, gen.pin, gen.rutaNist,
					gen.rutaCertificadoFTP);

			gen.writeToFile(file);
		} catch (ValidarDatosEntradaException ex) {
			log.info(ex);
		} catch (GenerarArchivoPKCS7Exception ex) {
			log.info(ex);
		} catch (Exception ex) {
			ex.printStackTrace();
			log.info(new IniciarAplicacionException("Error al iniciar la aplicaci�n"));
		}
	}

	public void setRutaNist(String ruta) throws ValidarDatosEntradaException {
		try {
			File file = new File(ruta);
			if (!file.exists()) {
				log.error("El archivo " + ruta + " no existe");
			} else if (!file.canRead()) {
				log.error("El archivo " + ruta + " no se puede leer");
			} else if (!ruta.endsWith(".nist") && !ruta.endsWith(".NIST")) {
				log.error("El archivo " + ruta + " no tiene la exensi�n .nist");
			} else if (!validateXML(ruta)) {
				log.error("El archivo " + ruta + " no es un xml valido");
			} else {
				this.rutaNist = file;
				return;
			}
		} catch (Exception ex) {
			ex.printStackTrace();
			throw new ValidarDatosEntradaException("No se pudo leer o no existe el archivo NIST " + ruta);
		}
		throw new ValidarDatosEntradaException("No se pudo leer o no existe el archivo NIST " + ruta);
	}

	public void setRutaKeystore(String ruta) throws ValidarDatosEntradaException {
		try {
			File file = new File(ruta);
			if (!file.exists()) {
				log.error("El archivo " + ruta + " no existe");
			} else if (!file.canRead()) {
				log.error("El archivo " + ruta + " no se puede leer");
			} else if (!ruta.endsWith(".p12") && !ruta.endsWith(".P12")) {
				log.error("El archivo " + ruta + " no tiene la exensi�n .p12");
			} else {
				this.rutaKeystore = file;
				return;
			}
		} catch (Exception ex) {
			ex.printStackTrace();
			throw new ValidarDatosEntradaException("No se pudo leer o no existe el archivo " + ruta);
		}
		throw new ValidarDatosEntradaException("No se pudo leer o no existe el archivo " + ruta);
	}

	public void setPin(String pin) throws ValidarDatosEntradaException {
		try {
			if (pin.length() < 8 || pin.length() > 15) {
				log.error("La longitud del pin ingresado es mayor a 15 o menor a 8 caracteres");
			} else if (!pin.matches("[A-Za-z0-9]{8,15}")) {
				log.error("El pin solo debe contener n�meros y letras");
			} else if (!this.pkcs7Service.verifyKeystore(this.rutaKeystore, pin)) {
				log.error("El pin no corresponde con el keystore proporcionado");
			} else {
				this.pin = pin;
				return;
			}
		} catch (Exception ex) {
			ex.printStackTrace();
			throw new ValidarDatosEntradaException("PIN incorrecto");
		}
		throw new ValidarDatosEntradaException("PIN incorrecto");
	}

	public void setRutaCertificadoFtp(String ruta) throws ValidarDatosEntradaException {
		try {
			File file = new File(ruta);
			if (!file.exists()) {
				log.error("El archivo " + ruta + " no existe");
			} else if (!file.canRead()) {
				log.error("El archivo " + ruta + " no se puede leer");
			} else if (!ruta.endsWith(".cer") && !ruta.endsWith(".CER")) {
				log.error("El archivo " + ruta + " no tiene la exensi�n .cer");
			} else {
				this.rutaCertificadoFTP = file;
				return;
			}
		} catch (Exception ex) {
			ex.printStackTrace();
			throw new ValidarDatosEntradaException("No se pudo leer o no existe el archivo " + ruta);
		}
		throw new ValidarDatosEntradaException("No se pudo leer o no existe el archivo " + ruta);
	}

	public void setRutaArchivoSalida(String ruta) throws ValidarDatosEntradaException {
		try {
			File file = new File(ruta);
			if (!file.exists()) {
				log.error("El directorio " + ruta + " no existe");
			} else if (!file.canWrite()) {
				log.error("En el directorio " + ruta + " no se puede escribir");
			} else {
				this.rutaArchivoSalida = file;
				return;
			}
		} catch (Exception ex) {
			ex.printStackTrace();
			throw new ValidarDatosEntradaException(
					"No existe o no se tiene permisos de escritura en el directorio " + ruta);
		}
		throw new ValidarDatosEntradaException(
				"No existe o no se tiene permisos de escritura en el directorio " + ruta);
	}

	public void setCurpResponsable(String curp) throws ValidarDatosEntradaException {
		try {
			if (curp.length() != 18) {
				log.error("La longitud de la CURP debe ser de 18 caracteres " + curp);
			} else if (!curp.matches("[A-Z]{4}[0-9]{6}[HM][A-Z]{5}[A-Z0-9]{2}")) {
				log.error("El formato de la CURP ingresada no es valido " + curp);
			} else {
				this.curpResponsable = curp;
				return;
			}
		} catch (Exception ex) {
			ex.printStackTrace();
			throw new ValidarDatosEntradaException("CURP del responsable incorrecta");
		}
		throw new ValidarDatosEntradaException("CURP del responsable incorrecta");
	}

	public void setNoEquipo(String noEquipo) throws ValidarDatosEntradaException {
		try {
			if (noEquipo.length() != 4) {
				log.error("La longitud del no. de quipo debe ser de 4 caracteres " + noEquipo);
			} else if (!noEquipo.matches("[0-9]{4}")) {
				log.error("El formato de no. de equipo no es valido " + noEquipo);
			} else {
				this.noEquipo = noEquipo;
				return;
			}
		} catch (Exception ex) {
			ex.printStackTrace();
			throw new ValidarDatosEntradaException("El No. de equipo debe contener �icamente digitos");
		}
		throw new ValidarDatosEntradaException("El No. de equipo debe contener �nicamente digitos");
	}

	public void setPkcs7Service(PKCS7Service pkcs7Service) {
		this.pkcs7Service = pkcs7Service;
	}

	public File writeToFile(byte[] data) throws GenerarArchivoPKCS7Exception {
		try {
			StringBuilder fileName = new StringBuilder();
			fileName.append(this.noEquipo);
			fileName.append((new SimpleDateFormat("ddMMyyyyHHmmss")).format(new Date()));
			fileName.append(this.curpResponsable);
			fileName.append(".ln2015");
			fileName.append(".p7m");
			fileName.append(".");
			fileName.append(String.format("%x", new Object[] { Integer.valueOf(data.length) }));
			File file = new File(this.rutaArchivoSalida, fileName.toString().toUpperCase());
			FileOutputStream fos = new FileOutputStream(file);
			BufferedOutputStream bos = new BufferedOutputStream(fos);
			bos.write(data);
			bos.close();
			log.info("Se genero el archivo " + file.getAbsolutePath());
			return file;
		} catch (Exception ex) {
			ex.printStackTrace();
			throw new GenerarArchivoPKCS7Exception("Error al generar el archivo PKCS7");
		}
	}

	public File getRutaNist() {
		return this.rutaNist;
	}

	public File getRutaKeystore() {
		return this.rutaKeystore;
	}

	public String getPin() {
		return this.pin;
	}

	public File getRutaCertificadoFTP() {
		return this.rutaCertificadoFTP;
	}

	public File getRutaArchivoSalida() {
		return this.rutaArchivoSalida;
	}

	public String getCurpResponsable() {
		return this.curpResponsable;
	}

	public String getNoEquipo() {
		return this.noEquipo;
	}

	private boolean validateXML(String file) throws ParserConfigurationException, SAXException, IOException {
		SAXParserFactory factory = SAXParserFactory.newInstance();
		factory.setValidating(false);
		factory.setNamespaceAware(true);

		SAXParser parser = factory.newSAXParser();

		XMLReader reader = parser.getXMLReader();
		reader.setErrorHandler(new ErrorHandler() {
			public void warning(SAXParseException e) throws SAXException {
				PKCS7Generator.log.error(e.getMessage());
			}

			public void error(SAXParseException e) throws SAXException {
				PKCS7Generator.log.error(e.getMessage());
			}

			public void fatalError(SAXParseException e) throws SAXException {
				PKCS7Generator.log.error(e.getMessage());
			}
		});

		try {
			reader.parse(new InputSource(file));
			return true;
		} catch (SAXException ex) {
			return false;
		}
	}
}
