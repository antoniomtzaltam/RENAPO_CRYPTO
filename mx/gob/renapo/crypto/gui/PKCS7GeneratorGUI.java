/*     */ package mx.gob.renapo.crypto.gui;
/*     */ 
/*     */ import java.awt.Dimension;
/*     */ import java.awt.FlowLayout;
/*     */ import java.awt.GridLayout;
/*     */ import java.awt.event.ActionEvent;
/*     */ import java.awt.event.ActionListener;
/*     */ import java.io.File;
/*     */ import javax.swing.JButton;
/*     */ import javax.swing.JFrame;
/*     */ import javax.swing.JLabel;
/*     */ import javax.swing.JOptionPane;
/*     */ import javax.swing.JPanel;
/*     */ import javax.swing.JPasswordField;
/*     */ import javax.swing.JTextField;
/*     */ import javax.swing.SwingUtilities;
/*     */ import mx.gob.renapo.crypto.PKCS7Generator;
/*     */ import mx.gob.renapo.crypto.exception.GenerarArchivoPKCS7Exception;
/*     */ import mx.gob.renapo.crypto.exception.ValidarDatosEntradaException;
/*     */ import mx.gob.renapo.crypto.service.PKCS7Service;
/*     */ import mx.gob.renapo.crypto.service.PKCS7ServiceImpl;
/*     */ import org.apache.log4j.Logger;
 
/*     */ public class PKCS7GeneratorGUI
/*     */   extends JPanel
/*     */ {
/*  30 */   private static Logger log = Logger.getLogger(PKCS7GeneratorGUI.class);
/*     */   private static final String LABEL_RUTA_NIST = "Ruta Archivo NIST:";
/*     */   private static final String LABEL_RUTA_KEYSTORE = "Ruta Archivo Keystore PKCS12:";
/*     */   private static final String LABEL_PIN = "PIN:";
/*     */   private static final String LABEL_RUTA_CERT_FTP = "Ruta Certificado de Cifrado:";
/*     */   private static final String LABEL_RUTA_ARCH_SALIDA = "Ruta Archivo P7M Salida:";
/*     */   private static final String LABEL_CURP = "CURP Responsable:";
/*     */   private static final String LABEL_NO_EQUIPO = "No. equipo registrado dependencia:";
/*     */   private static final String LABEL_LIMPIAR = "Limpiar";
/*     */   private static final String LABEL_ACEPTAR = "Aceptar";
/*     */   private static final int COLUMNS = 50;
/*     */   private JTextField[] fields;
/*  42 */   private PKCS7Generator gen = new PKCS7Generator();
/*  43 */   private PKCS7Service pkcs7Service = (PKCS7Service)new PKCS7ServiceImpl();
/*     */ 
/*     */ 
/*     */ 
/*     */   
/*     */   public static void main(String[] args) {
/*  49 */     SwingUtilities.invokeLater(new Runnable() {
/*     */           public void run() {
/*  51 */             PKCS7GeneratorGUI.createAndShowGUI();
/*     */           }
/*     */         });
/*     */   }
/*     */ 
/*     */ 
/*     */   
/*     */   public PKCS7GeneratorGUI() {
/*  59 */     JPanel labelPanel = new JPanel(new GridLayout(7, 1));
/*  60 */     JPanel fieldPanel = new JPanel(new GridLayout(7, 1));
/*     */     
/*  62 */     add(labelPanel, "West");
/*  63 */     add(fieldPanel, "Center");
/*     */     
/*  65 */     String[] labels = { "Ruta Archivo NIST:", "Ruta Archivo Keystore PKCS12:", "PIN:", "Ruta Certificado de Cifrado:", 
/*  66 */         "Ruta Archivo P7M Salida:", "CURP Responsable:", "No. equipo registrado dependencia:" };
/*  67 */     this.fields = new JTextField[labels.length];
/*     */ 
/*     */     
/*  70 */     for (int i = 0; i < this.fields.length; i++) {
/*  71 */       if (labels[i].equals("PIN:")) {
/*  72 */         this.fields[i] = new JPasswordField();
/*     */       } else {
/*  74 */         this.fields[i] = new JTextField();
/*     */       } 
/*     */       
/*  77 */       this.fields[i].setColumns(50);
/*  78 */       JPanel p = new JPanel(new FlowLayout(0));
/*     */ 
/*     */       
/*  81 */       p.add(this.fields[i]);
/*  82 */       fieldPanel.add(p);
/*  83 */       JLabel label = new JLabel(labels[i], 4);
/*  84 */       label.setLabelFor(this.fields[i]);
/*  85 */       label.setPreferredSize(new Dimension((label.getPreferredSize()).width, (p.getPreferredSize()).height));
/*  86 */       labelPanel.add(label);
/*     */     } 
/*     */     
/*  89 */     this.gen.setPkcs7Service(this.pkcs7Service);
/*     */   }
/*     */   
/*     */   private void clean() {
/*  93 */     for (int i = 0; i < this.fields.length; i++) {
/*  94 */       this.fields[i].setText("");
/*     */     }
/*     */   }
/*     */ 
/*     */   
/*     */   private void submit() {
/*     */     try {
/* 101 */       this.gen.setRutaNist(this.fields[0].getText().trim());
/* 102 */       this.gen.setRutaKeystore(this.fields[1].getText().trim());
/* 103 */       this.gen.setPin(this.fields[2].getText().trim());
/* 104 */       this.gen.setRutaCertificadoFtp(this.fields[3].getText().trim());
/* 105 */       this.gen.setRutaArchivoSalida(this.fields[4].getText().trim());
/* 106 */       this.gen.setCurpResponsable(this.fields[5].getText().trim());
/* 107 */       this.gen.setNoEquipo(this.fields[6].getText().trim());
/*     */       
/* 109 */       byte[] data = this.pkcs7Service.generateFile(this.gen.getRutaKeystore(), this.gen.getPin(), this.gen.getRutaNist(), this.gen.getRutaCertificadoFTP());
/*     */       
/* 111 */       File file = this.gen.writeToFile(data);
/*     */       
/* 113 */       JOptionPane.showMessageDialog(this, 
/* 114 */           "Se genero el archivo " + file.getAbsolutePath(), 
/* 115 */           "Archivo generado exitosamente", 
/* 116 */           1);
/*     */     
/*     */     }
/* 119 */     catch (ValidarDatosEntradaException ex) {
/* 120 */       JOptionPane.showMessageDialog(this, 
/* 121 */           ex.getMessage(), 
/* 122 */           "Error de validaciÃ³n de datos de entrada", 
/* 123 */           0);
/* 124 */       log.info(ex);
/* 125 */     } catch (GenerarArchivoPKCS7Exception ex) {
/* 126 */       JOptionPane.showMessageDialog(this, 
/* 127 */           ex.getMessage(), 
/* 128 */           "Error al crear el archivo PKCS7", 
/* 129 */           0);
/* 130 */       log.info(ex);
/* 131 */     } catch (Exception ex) {
/* 132 */       JOptionPane.showMessageDialog(this, 
/* 133 */           ex.getMessage(), 
/* 134 */           "Error al iniciar la aplicaciÃ³n", 
/* 135 */           0);
/*     */     } 
/*     */   }
/*     */ 
/*     */   
/*     */   private static void createAndShowGUI() {
/* 141 */     JFrame frame = new JFrame("Generador PKCS7");
/* 142 */     frame.setDefaultCloseOperation(3);
/* 143 */     final PKCS7GeneratorGUI gui = new PKCS7GeneratorGUI();
/*     */ 
/*     */     
/* 146 */     JButton cleanButton = new JButton("Limpiar");
/* 147 */     JButton submitButton = new JButton("Aceptar");
/* 148 */     JPanel botones = new JPanel();
/* 149 */     botones.add(cleanButton);
/* 150 */     botones.add(submitButton);
/* 151 */     submitButton.addActionListener(new ActionListener()
/*     */         {
/*     */           public void actionPerformed(ActionEvent e)
/*     */           {
/* 155 */             gui.submit();
/*     */           }
/*     */         });
/*     */     
/* 159 */     cleanButton.addActionListener(new ActionListener()
/*     */         {
/*     */           public void actionPerformed(ActionEvent arg0)
/*     */           {
/* 163 */             gui.clean();
/*     */           }
/*     */         });
/*     */ 
/*     */ 
/*     */     
/* 169 */     frame.getContentPane().add(gui, "North");
/* 170 */     frame.getContentPane().add(botones, "South");
/*     */ 
/*     */     
/* 173 */     frame.pack();
/* 174 */     frame.setResizable(false);
/* 175 */     frame.setVisible(true);
/*     */   }
/*     */ }


/* Location:              C:\Trabajo\P7M\PKCS7Generator.jar!\mx\gob\renapo\crypto\gui\PKCS7GeneratorGUI.class
 * Java compiler version: 6 (50.0)
 * JD-Core Version:       1.1.3
 */