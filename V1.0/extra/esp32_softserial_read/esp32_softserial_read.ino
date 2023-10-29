#include <SoftwareSerial.h>
SoftwareSerial mySerial(18, 19);

String get_rfid_card(){
  mySerial.begin(4800);
  delayMicroseconds(200);
  String inp_from_arduino;
  char inByte = 0;
  while (inByte != '\n'){
    while (mySerial.available() > 0) {
      inByte = mySerial.read();
      if (inByte != '\n')
        inp_from_arduino += inByte;
    }
  }
  mySerial.end();
  return inp_from_arduino;
}

void setup() {
  Serial.begin(115200);

}

void loop() {
  Serial.println(get_rfid_card());
}
