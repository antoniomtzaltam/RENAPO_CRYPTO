/*    */ package org.apache.commons.codec;
/*    */ 
/*    */ import java.util.Comparator;
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ public class StringEncoderComparator
/*    */   implements Comparator
/*    */ {
/*    */   private final StringEncoder stringEncoder;
/*    */   
/*    */   public StringEncoderComparator() {
/* 44 */     this.stringEncoder = null;
/*    */   }
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */   
/*    */   public StringEncoderComparator(StringEncoder stringEncoder) {
/* 54 */     this.stringEncoder = stringEncoder;
/*    */   }
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */ 
/*    */   
/*    */   public int compare(Object o1, Object o2) {
/* 72 */     int compareCode = 0;
/*    */     
/*    */     try {
/* 75 */       Comparable s1 = (Comparable)this.stringEncoder.encode(o1);
/* 76 */       Comparable s2 = (Comparable)this.stringEncoder.encode(o2);
/* 77 */       compareCode = s1.compareTo(s2);
/* 78 */     } catch (EncoderException ee) {
/* 79 */       compareCode = 0;
/*    */     } 
/* 81 */     return compareCode;
/*    */   }
/*    */ }


/* Location:              C:\Trabajo\P7M\PKCS7Generator.jar!\org\apache\commons\codec\StringEncoderComparator.class
 * Java compiler version: 4 (48.0)
 * JD-Core Version:       1.1.3
 */