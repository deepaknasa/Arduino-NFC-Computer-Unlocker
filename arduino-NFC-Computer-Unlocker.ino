#include <Wire.h>
#include <Adafruit_NFCShield_I2C.h>
#include <AESLib.h>
#define IRQ 6 // this trace must be cut and rewired!
#define RESET 8

Adafruit_NFCShield_I2C nfc(IRQ, RESET);
//SETUP

void setup() {
  //Set up Serial library at 9600 bps
  Serial.begin(9600);
  //Find Adafruit RFID/NFC shield
  nfc.begin();
  uint32_t versiondata = nfc.getFirmwareVersion();

  if(! versiondata) {
    Serial.print("Didn't find PN53x board");
    while (1); // halt
  }

  //Got ok data, print it out!
  Serial.print("Found chip PN5"); Serial.println((versiondata>>24) & 0xFF, HEX);
  Serial.print("Firmware ver. "); Serial.print((versiondata>>16) & 0xFF, DEC);
  Serial.print('.'); Serial.println((versiondata>>8) & 0xFF, DEC);

  //Configure board to read RFID tags
  nfc.SAMConfig();
  Keyboard.begin(); //initiate the Keyboard
}

//LOOP
unsigned digit = 0;

void loop() {
  uint8_t success;
  uint8_t uid[] = { 0, 0, 0, 0, 0, 0, 0 }; // Buffer to store the returned UID
  uint8_t uidLength; // Length of the UID (4 or 7 bytes depending on ISO14443A tag type)

  //Wait for RFID tag to show up!
  Serial.println("Waiting for an ISO14443A tag ...");

  //Wait for an ISO14443A type tags (Mifare, etc.). When one is found
  // 'uid' will be populated with the UID, and uidLength will indicate
  // if the uid is 4 bytes (Mifare Classic) or 7 bytes (Mifare Ultralight)
  success = nfc.readPassiveTargetID(PN532_MIFARE_ISO14443A, uid, &uidLength);
  uint32_t tagID = 0;
  uint32_t tagEncKey = 0; //Used to create an key to decrypt password
  
  if(success) {
    // Found a tag!
    //Serial.print("Tag detected #");
    //turn the four byte UID of a mifare classic into a single variable #
    tagID = uid[3];
    tagID <<= 8; tagID |= uid[2];
    tagID <<= 8; tagID |= uid[1];
    tagID <<= 8; tagID |= uid[0];
    
    tagEncKey = uid[3];
    tagEncKey <<= 8; tagEncKey |= uid[3];
    tagEncKey <<= 8; tagEncKey |= uid[2];
    tagEncKey <<= 8; tagEncKey |= uid[1];

    uint8_t key[] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
    int i = 0;
    
    //Populate the encryption key with values from tagEncKey
    //Source: http://stackoverflow.com/a/15987717
    while(tagEncKey) { //loop till there's nothing left
        key[i++] = (tagEncKey % 10); // assign the last digit
        tagEncKey /= 10; // "right shift" the number
    }
    
    //Work Computer
    if(tagID == 843203076) {
      Keyboard.press(KEY_LEFT_CTRL);
      Keyboard.press(KEY_LEFT_ALT);
      Keyboard.press(KEY_DELETE);
      delay(100); //Wait for login form to appear
      Keyboard.releaseAll();

      /** 
        * Make changes here
        */
      int32_t passwordLength = 11;
      /*
      //If you need to change your password, use the following lines to encrypt the new password.
      //TIP: Make sure to comment out the ctrl-alt-delete code above before running
      char password[] = "secretpass!"; //Delete this unencrypted password before using in production 
      printEncryptedPasswordByKey(password, passwordLength, key);
      */
      //Paste encrypted password encoded in decimal from serial monitor here.
      //Encrypted and encoded password chunks:
      char chunks[1][16] ={{72,82,14,152,86,146,10,243,190,176,112,91,154,181,52,35}};
      /** 
        * End making changes 
        */
      
      int32_t n_chunks = sizeof(chunks)/sizeof(chunks[0]);
      char* decryptedPassword = decryptPasswordByKey(chunks, n_chunks, key);
      KeyboardWritePass(decryptedPassword, passwordLength);
      Keyboard.write(KEY_RETURN);
      delay(1500); //makes sure the password isn't repeated
    }
    
    //Password Manager
    if(tagID == 844972804) {
      /** 
        * Make changes here
        */
      int32_t passwordLength = 19;
      /*
      //If you need to change your password, use the following lines to encrypt the new password
      char password[] = "secretpassissecret!"; //Delete this unencrypted password before using in production 
      printEncryptedPasswordByKey(password, passwordLength, key);
      */
      
      //Paste encrypted password encoded in decimal from serial monitor here.
      //Encrypted and encoded password chunks:
      char chunks[2][16] ={{131,117,195,246,172,67,117,13,126,136,216,66,176,90,71,0},
        {217,216,161,106,208,167,214,26,148,252,52,246,166,134,6,96}
      };
      /**
        * End making changes 
        */
      
      int32_t n_chunks = sizeof(chunks)/sizeof(chunks[0]);
      char* decryptedPassword = decryptPasswordByKey(chunks, n_chunks, key);
      KeyboardWritePass(decryptedPassword, passwordLength);
      Keyboard.write(KEY_RETURN);
      delay(1500);
   }
  }
}

//function
void printEncryptedPasswordByKey(char *password, size_t passwordLength, uint8_t *key) {
  int32_t n_bytes = passwordLength;
  //Long passwords must be split into 16 byte chunks for AES encryption lib
  int32_t chunksize = 16;
  int32_t n_chunks = n_bytes/chunksize + (n_bytes % chunksize ? 1 : 0);
  size_t i, j;
  
  //Chunk the password into the chunks two-dimensional array
  uint8_t chunks[n_chunks][chunksize];
  memset(chunks, 0, sizeof(uint8_t[n_chunks][chunksize]));
  memcpy(chunks, password, n_bytes);
  
  //Encrypt the password chunks with the given key
  for(i = 0; i < n_chunks; i++) {
    aes128_enc_single(key, chunks[i]);
  }
  
  Serial.print("char chunks[" + (String)n_chunks + "][" + (String)chunksize + "] ={");
  
  //Print our encrypted password chunks in decimal (int).
  for(i = 0; i < n_chunks; i++) {
    Serial.print("{");
    
    for(j = 0; j < chunksize; j++) {
      Serial.print((int)chunks[i][j]);
      
      if(j != (chunksize - 1)) {
        Serial.print(",");
      }
    }
    
    Serial.println("}");
    
    if(i != (n_chunks - 1)) {
      Serial.print(",");
    }
  }
  
  Serial.println("};");
}

//function
char* decryptPasswordByKey(char chunks[][16], int32_t n_chunks, uint8_t *key) {
  static char decryptedPassword[32];
  size_t i, j, k;
  
  //Decrypt password
  for(i = 0; i < n_chunks; i++) {
    aes128_dec_single(key, chunks[i]);
  }
  
  for(i = 0, k = 0; i < n_chunks; i++) {
    for(j = 0; j < 16; j++){
      decryptedPassword[k] = chunks[i][j];
      k++;
    }
  }
  
  return decryptedPassword;
}

//function
void KeyboardWritePass(char s[], int32_t passwordLength) {
  size_t i;
  
  if(s != NULL && s != "") {
    for (i = 0; i < passwordLength; i++){
      Keyboard.write(s[i]);
    }
  }
}
