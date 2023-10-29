/*
KhadashPay Firebase Edition
Distributed under the MIT License
© Copyright Maxim Bortnikov 2023
For more information please visit
https://sourceforge.net/projects/khadashpay-firebase-edition/
https://github.com/Northstrix/KhadashPay-Firebase-Edition
Required libraries:
https://github.com/zhouyangchao/AES
https://github.com/peterferrie/serpent
https://github.com/ddokkaebi/Blowfish
https://github.com/Northstrix/DES_and_3DES_Library_for_MCUs
https://github.com/ulwanski/sha512
https://github.com/Bodmer/TFT_eSPI
https://github.com/intrbiz/arduino-crypto
https://github.com/miguelbalboa/rfid
https://github.com/techpaul/PS2KeyAdvanced
https://github.com/techpaul/PS2KeyMapv
https://github.com/mobizt/Firebase-ESP32
https://github.com/plerup/espsoftwareserial
https://github.com/Chris--A/Keypad
https://github.com/Harvie/ps2dev
*/
// !!! Before uploading this sketch -
// Switch the partition scheme to the
// "Huge APP (3MB No OTA/1MB SPIFFS)" !!!
#include <Arduino.h>
#include <WiFi.h>
#include <FirebaseESP32.h>
#include "addons/TokenHelper.h"
#include "addons/RTDBHelper.h"
#include "DES.h"
#include "aes.h"
#include "blowfish.h"
#include "serpent.h"
#include "Crypto.h"
#include "khadashpaypictures.h"
#include "sha512.h"
#include <TFT_eSPI.h>
#include <SoftwareSerial.h>
#include <PS2KeyAdvanced.h>
#include <PS2KeyMap.h>

#define IRQPIN 22
#define DATAPIN 23

#define MAX_NUM_OF_RECS 999

#define DELAY_FOR_SLOTS 200

TFT_eSPI tft = TFT_eSPI();
TFT_eSprite mvng_bc = TFT_eSprite( & tft);

DES des;
Blowfish blowfish;

PS2KeyAdvanced keyboard;
PS2KeyMap keymap;

SoftwareSerial mySerial(18, 19);

FirebaseData fbdo;
FirebaseAuth auth;
FirebaseConfig config;

String fuid = ""; 
bool isAuthenticated = false;

uint16_t code;

int read_card_rec_from_arduino[4];

int m;
String dec_st;
String dec_tag;
byte tmp_st[8];
int pass_to_serp[16];
int decract;
byte array_for_CBC_mode[10];
uint16_t c;
String keyboard_input;
int curr_key;
bool finish_input;
bool act;
bool decrypt_tag;
const uint16_t current_inact_clr = 0x051b;
const uint16_t five_six_five_red_color = 0xf940;
bool cont_t_nxt;
int menu_pos;
bool gen_r;
String space_and_currency = " USD"; // Space + Currency name
int text_size_for_sale = 3;
bool cont_to_next_step = true;

#define WIFI_SSID "accessPpointName"
#define WIFI_PASSWORD "accessPointPassword"
#define API_KEY "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
#define DATABASE_URL "https://database-name-default-rtdb.firebaseio.com/"

// Keys (Below)
byte read_cards[16] = {
0xca,0x1f,0xff,0xc6,0x34,0x91,0x2d,0x7a,
0xf0,0x60,0xec,0xb5,0xba,0x1d,0x1a,0xff
};
String kderalgs = "4DSq75Q3PcHZ6P8b1lqrC";
int numofkincr = 787;
byte hmackey[] = {"6v22J37H25wD108KcgP6n6MyIzUTQr2jKJ7L5w5qDhFsaqzbt15MIQV71dJ8Tv8U214SwN69EDwVJD21o8tAYgAc9Sp8aaYJXfeM7co0wim0FFQ3C7e0bRA"};
byte des_key[] = {
0xf7,0xee,0xf4,0x90,0xb9,0xa6,0xb4,0xfe,
0xc5,0x88,0x8a,0x1b,0xcc,0x2d,0xfe,0x6c,
0xec,0x2c,0x0f,0x3d,0xbf,0xeb,0xa4,0xef
};
uint8_t AES_key[32] = {
0xe9,0x56,0xbe,0xde,
0x35,0x3b,0xad,0xfa,
0xd7,0x7a,0xe5,0x91,
0xcd,0x1e,0x64,0x1d,
0x13,0x1e,0x93,0x5d,
0x47,0x4c,0xe6,0x3f,
0xe1,0x54,0xa7,0x80,
0xfe,0xea,0xbb,0xdf
};
unsigned char Blwfsh_key[] = {
0x6d,0xd7,0xbd,0x88,
0x3a,0xcd,0xfb,0x34,
0x10,0x20,0x42,0xb4,
0xac,0x50,0x6a,0xdd,
0x0a,0xad,0xc8,0x5e,
0xa9,0xad,0x32,0x35
};
uint8_t serp_key[32] = {
0x9f,0xae,0x9a,0x68,
0xbf,0xfa,0x96,0x6a,
0xfb,0xb7,0xcc,0xec,
0xc3,0x1c,0xc8,0xf4,
0x1d,0x1f,0xfa,0xff,
0xc8,0xd7,0x12,0xa1,
0xf5,0x9b,0x16,0xa7,
0xe3,0xb3,0xdb,0x76
};
uint8_t second_AES_key[32] = {
0x59,0x6e,0x7a,0x4e,
0xc7,0x12,0x8b,0x12,
0x9c,0xcd,0xb6,0x9c,
0x58,0xfe,0x7d,0x7b,
0x96,0xe9,0x1a,0x54,
0xba,0x00,0x42,0xd8,
0x0d,0xde,0x7a,0xfe,
0xa7,0xe6,0xc5,0xaa
};
// Keys (Above)

byte back_des_key[24];
uint8_t back_serp_key[32];
unsigned char back_Blwfsh_key[16];
uint8_t back_AES_key[32];
uint8_t back_s_AES_key[32];
uint8_t back_def_serp_key[32];

void back_def_serp_k() {
  for (int i = 0; i < 32; i++) {
    back_def_serp_key[i] = serp_key[i];
  }
}

void rest_def_serp_k() {
  for (int i = 0; i < 32; i++) {
    serp_key[i] = back_def_serp_key[i];
  }
}

void back_serp_k() {
  for (int i = 0; i < 32; i++) {
    back_serp_key[i] = serp_key[i];
  }
}

void rest_serp_k() {
  for (int i = 0; i < 32; i++) {
    serp_key[i] = back_serp_key[i];
  }
}

void back_Bl_k() {
  for (int i = 0; i < 16; i++) {
    back_Blwfsh_key[i] = Blwfsh_key[i];
  }
}

void rest_Bl_k() {
  for (int i = 0; i < 16; i++) {
    Blwfsh_key[i] = back_Blwfsh_key[i];
  }
}

void back_AES_k() {
  for (int i = 0; i < 32; i++) {
    back_AES_key[i] = AES_key[i];
  }
}

void rest_AES_k() {
  for (int i = 0; i < 32; i++) {
    AES_key[i] = back_AES_key[i];
  }
}

void back_3des_k() {
  for (int i = 0; i < 24; i++) {
    back_des_key[i] = des_key[i];
  }
}

void rest_3des_k() {
  for (int i = 0; i < 24; i++) {
    des_key[i] = back_des_key[i];
  }
}

void back_second_AES_key() {
  for (int i = 0; i < 32; i++) {
    back_s_AES_key[i] = second_AES_key[i];
  }
}

void rest_second_AES_key() {
  for (int i = 0; i < 32; i++) {
    second_AES_key[i] = back_s_AES_key[i];
  }
}

void incr_des_key() {
  if (des_key[7] == 255) {
    des_key[7] = 0;
    if (des_key[6] == 255) {
      des_key[6] = 0;
      if (des_key[5] == 255) {
        des_key[5] = 0;
        if (des_key[4] == 255) {
          des_key[4] = 0;
          if (des_key[3] == 255) {
            des_key[3] = 0;
            if (des_key[2] == 255) {
              des_key[2] = 0;
              if (des_key[1] == 255) {
                des_key[1] = 0;
                if (des_key[0] == 255) {
                  des_key[0] = 0;
                } else {
                  des_key[0]++;
                }
              } else {
                des_key[1]++;
              }
            } else {
              des_key[2]++;
            }
          } else {
            des_key[3]++;
          }
        } else {
          des_key[4]++;
        }
      } else {
        des_key[5]++;
      }
    } else {
      des_key[6]++;
    }
  } else {
    des_key[7]++;
  }

  if (des_key[15] == 255) {
    des_key[15] = 0;
    if (des_key[14] == 255) {
      des_key[14] = 0;
      if (des_key[13] == 255) {
        des_key[13] = 0;
        if (des_key[12] == 255) {
          des_key[12] = 0;
          if (des_key[11] == 255) {
            des_key[11] = 0;
            if (des_key[10] == 255) {
              des_key[10] = 0;
              if (des_key[9] == 255) {
                des_key[9] = 0;
                if (des_key[8] == 255) {
                  des_key[8] = 0;
                } else {
                  des_key[8]++;
                }
              } else {
                des_key[9]++;
              }
            } else {
              des_key[10]++;
            }
          } else {
            des_key[11]++;
          }
        } else {
          des_key[12]++;
        }
      } else {
        des_key[13]++;
      }
    } else {
      des_key[14]++;
    }
  } else {
    des_key[15]++;
  }

  if (des_key[23] == 255) {
    des_key[23] = 0;
    if (des_key[22] == 255) {
      des_key[22] = 0;
      if (des_key[21] == 255) {
        des_key[21] = 0;
        if (des_key[20] == 255) {
          des_key[20] = 0;
          if (des_key[19] == 255) {
            des_key[19] = 0;
            if (des_key[18] == 255) {
              des_key[18] = 0;
              if (des_key[17] == 255) {
                des_key[17] = 0;
                if (des_key[16] == 255) {
                  des_key[16] = 0;
                } else {
                  des_key[16]++;
                }
              } else {
                des_key[17]++;
              }
            } else {
              des_key[18]++;
            }
          } else {
            des_key[19]++;
          }
        } else {
          des_key[20]++;
        }
      } else {
        des_key[21]++;
      }
    } else {
      des_key[22]++;
    }
  } else {
    des_key[23]++;
  }
}

void incr_AES_key() {
  if (AES_key[0] == 255) {
    AES_key[0] = 0;
    if (AES_key[1] == 255) {
      AES_key[1] = 0;
      if (AES_key[2] == 255) {
        AES_key[2] = 0;
        if (AES_key[3] == 255) {
          AES_key[3] = 0;
          if (AES_key[4] == 255) {
            AES_key[4] = 0;
            if (AES_key[5] == 255) {
              AES_key[5] = 0;
              if (AES_key[6] == 255) {
                AES_key[6] = 0;
                if (AES_key[7] == 255) {
                  AES_key[7] = 0;
                  if (AES_key[8] == 255) {
                    AES_key[8] = 0;
                    if (AES_key[9] == 255) {
                      AES_key[9] = 0;
                      if (AES_key[10] == 255) {
                        AES_key[10] = 0;
                        if (AES_key[11] == 255) {
                          AES_key[11] = 0;
                          if (AES_key[12] == 255) {
                            AES_key[12] = 0;
                            if (AES_key[13] == 255) {
                              AES_key[13] = 0;
                              if (AES_key[14] == 255) {
                                AES_key[14] = 0;
                                if (AES_key[15] == 255) {
                                  AES_key[15] = 0;
                                } else {
                                  AES_key[15]++;
                                }
                              } else {
                                AES_key[14]++;
                              }
                            } else {
                              AES_key[13]++;
                            }
                          } else {
                            AES_key[12]++;
                          }
                        } else {
                          AES_key[11]++;
                        }
                      } else {
                        AES_key[10]++;
                      }
                    } else {
                      AES_key[9]++;
                    }
                  } else {
                    AES_key[8]++;
                  }
                } else {
                  AES_key[7]++;
                }
              } else {
                AES_key[6]++;
              }
            } else {
              AES_key[5]++;
            }
          } else {
            AES_key[4]++;
          }
        } else {
          AES_key[3]++;
        }
      } else {
        AES_key[2]++;
      }
    } else {
      AES_key[1]++;
    }
  } else {
    AES_key[0]++;
  }
}

void incr_Blwfsh_key() {
  if (Blwfsh_key[0] == 255) {
    Blwfsh_key[0] = 0;
    if (Blwfsh_key[1] == 255) {
      Blwfsh_key[1] = 0;
      if (Blwfsh_key[2] == 255) {
        Blwfsh_key[2] = 0;
        if (Blwfsh_key[3] == 255) {
          Blwfsh_key[3] = 0;
          if (Blwfsh_key[4] == 255) {
            Blwfsh_key[4] = 0;
            if (Blwfsh_key[5] == 255) {
              Blwfsh_key[5] = 0;
              if (Blwfsh_key[6] == 255) {
                Blwfsh_key[6] = 0;
                if (Blwfsh_key[7] == 255) {
                  Blwfsh_key[7] = 0;
                  if (Blwfsh_key[8] == 255) {
                    Blwfsh_key[8] = 0;
                    if (Blwfsh_key[9] == 255) {
                      Blwfsh_key[9] = 0;
                      if (Blwfsh_key[10] == 255) {
                        Blwfsh_key[10] = 0;
                        if (Blwfsh_key[11] == 255) {
                          Blwfsh_key[11] = 0;
                          if (Blwfsh_key[12] == 255) {
                            Blwfsh_key[12] = 0;
                            if (Blwfsh_key[13] == 255) {
                              Blwfsh_key[13] = 0;
                              if (Blwfsh_key[14] == 255) {
                                Blwfsh_key[14] = 0;
                                if (Blwfsh_key[15] == 255) {
                                  Blwfsh_key[15] = 0;
                                } else {
                                  Blwfsh_key[15]++;
                                }
                              } else {
                                Blwfsh_key[14]++;
                              }
                            } else {
                              Blwfsh_key[13]++;
                            }
                          } else {
                            Blwfsh_key[12]++;
                          }
                        } else {
                          Blwfsh_key[11]++;
                        }
                      } else {
                        Blwfsh_key[10]++;
                      }
                    } else {
                      Blwfsh_key[9]++;
                    }
                  } else {
                    Blwfsh_key[8]++;
                  }
                } else {
                  Blwfsh_key[7]++;
                }
              } else {
                Blwfsh_key[6]++;
              }
            } else {
              Blwfsh_key[5]++;
            }
          } else {
            Blwfsh_key[4]++;
          }
        } else {
          Blwfsh_key[3]++;
        }
      } else {
        Blwfsh_key[2]++;
      }
    } else {
      Blwfsh_key[1]++;
    }
  } else {
    Blwfsh_key[0]++;
  }
}

void incr_serp_key() {
  if (serp_key[15] == 255) {
    serp_key[15] = 0;
    if (serp_key[14] == 255) {
      serp_key[14] = 0;
      if (serp_key[13] == 255) {
        serp_key[13] = 0;
        if (serp_key[12] == 255) {
          serp_key[12] = 0;
          if (serp_key[11] == 255) {
            serp_key[11] = 0;
            if (serp_key[10] == 255) {
              serp_key[10] = 0;
              if (serp_key[9] == 255) {
                serp_key[9] = 0;
                if (serp_key[8] == 255) {
                  serp_key[8] = 0;
                  if (serp_key[7] == 255) {
                    serp_key[7] = 0;
                    if (serp_key[6] == 255) {
                      serp_key[6] = 0;
                      if (serp_key[5] == 255) {
                        serp_key[5] = 0;
                        if (serp_key[4] == 255) {
                          serp_key[4] = 0;
                          if (serp_key[3] == 255) {
                            serp_key[3] = 0;
                            if (serp_key[2] == 255) {
                              serp_key[2] = 0;
                              if (serp_key[1] == 255) {
                                serp_key[1] = 0;
                                if (serp_key[0] == 255) {
                                  serp_key[0] = 0;
                                } else {
                                  serp_key[0]++;
                                }
                              } else {
                                serp_key[1]++;
                              }
                            } else {
                              serp_key[2]++;
                            }
                          } else {
                            serp_key[3]++;
                          }
                        } else {
                          serp_key[4]++;
                        }
                      } else {
                        serp_key[5]++;
                      }
                    } else {
                      serp_key[6]++;
                    }
                  } else {
                    serp_key[7]++;
                  }
                } else {
                  serp_key[8]++;
                }
              } else {
                serp_key[9]++;
              }
            } else {
              serp_key[10]++;
            }
          } else {
            serp_key[11]++;
          }
        } else {
          serp_key[12]++;
        }
      } else {
        serp_key[13]++;
      }
    } else {
      serp_key[14]++;
    }
  } else {
    serp_key[15]++;
  }
}

void incr_second_AES_key() {
  if (second_AES_key[0] == 255) {
    second_AES_key[0] = 0;
    if (second_AES_key[1] == 255) {
      second_AES_key[1] = 0;
      if (second_AES_key[2] == 255) {
        second_AES_key[2] = 0;
        if (second_AES_key[3] == 255) {
          second_AES_key[3] = 0;
          if (second_AES_key[4] == 255) {
            second_AES_key[4] = 0;
            if (second_AES_key[5] == 255) {
              second_AES_key[5] = 0;
              if (second_AES_key[6] == 255) {
                second_AES_key[6] = 0;
                if (second_AES_key[7] == 255) {
                  second_AES_key[7] = 0;
                  if (second_AES_key[8] == 255) {
                    second_AES_key[8] = 0;
                    if (second_AES_key[9] == 255) {
                      second_AES_key[9] = 0;
                      if (second_AES_key[10] == 255) {
                        second_AES_key[10] = 0;
                        if (second_AES_key[11] == 255) {
                          second_AES_key[11] = 0;
                          if (second_AES_key[12] == 255) {
                            second_AES_key[12] = 0;
                            if (second_AES_key[13] == 255) {
                              second_AES_key[13] = 0;
                              if (second_AES_key[14] == 255) {
                                second_AES_key[14] = 0;
                                if (second_AES_key[15] == 255) {
                                  second_AES_key[15] = 0;
                                } else {
                                  second_AES_key[15]++;
                                }
                              } else {
                                second_AES_key[14]++;
                              }
                            } else {
                              second_AES_key[13]++;
                            }
                          } else {
                            second_AES_key[12]++;
                          }
                        } else {
                          second_AES_key[11]++;
                        }
                      } else {
                        second_AES_key[10]++;
                      }
                    } else {
                      second_AES_key[9]++;
                    }
                  } else {
                    second_AES_key[8]++;
                  }
                } else {
                  second_AES_key[7]++;
                }
              } else {
                second_AES_key[6]++;
              }
            } else {
              second_AES_key[5]++;
            }
          } else {
            second_AES_key[4]++;
          }
        } else {
          second_AES_key[3]++;
        }
      } else {
        second_AES_key[2]++;
      }
    } else {
      second_AES_key[1]++;
    }
  } else {
    second_AES_key[0]++;
  }
}

size_t hex2bin(void * bin) {
  size_t len, i;
  int x;
  uint8_t * p = (uint8_t * ) bin;
  for (i = 0; i < 32; i++) {
    p[i] = (uint8_t) serp_key[i];
  }
  return 32;
}

int getNum(char ch) {
  int num = 0;
  if (ch >= '0' && ch <= '9') {
    num = ch - 0x30;
  } else {
    switch (ch) {
    case 'A':
    case 'a':
      num = 10;
      break;
    case 'B':
    case 'b':
      num = 11;
      break;
    case 'C':
    case 'c':
      num = 12;
      break;
    case 'D':
    case 'd':
      num = 13;
      break;
    case 'E':
    case 'e':
      num = 14;
      break;
    case 'F':
    case 'f':
      num = 15;
      break;
    default:
      num = 0;
    }
  }
  return num;
}

char getChar(int num) {
  char ch;
  if (num >= 0 && num <= 9) {
    ch = char(num + 48);
  } else {
    switch (num) {
    case 10:
      ch = 'a';
      break;
    case 11:
      ch = 'b';
      break;
    case 12:
      ch = 'c';
      break;
    case 13:
      ch = 'd';
      break;
    case 14:
      ch = 'e';
      break;
    case 15:
      ch = 'f';
      break;
    }
  }
  return ch;
}

void back_keys() {
  back_3des_k();
  back_AES_k();
  back_Bl_k();
  back_serp_k();
  back_second_AES_key();
}

void rest_keys() {
  rest_3des_k();
  rest_AES_k();
  rest_Bl_k();
  rest_serp_k();
  rest_second_AES_key();
}

void clear_variables() {
  keyboard_input = "";
  dec_st = "";
  dec_tag = "";
  decract = 0;
  return;
}

int get_rnd_val() {
  if (gen_r == true)
    return esp_random() % 256;
  else
    return AES_key[1];
}

void get_input_from_arduino_uno(){
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
    delayMicroseconds(400);
  }
  mySerial.end();
  int inp_from_arduino_len = inp_from_arduino.length() + 1;
  char inp_from_arduino_array[inp_from_arduino_len];
  inp_from_arduino.toCharArray(inp_from_arduino_array, inp_from_arduino_len);
  for (int i = 0; i < 8; i += 2) {
    if (i == 0) {
      if (inp_from_arduino_array[i] != 0 && inp_from_arduino_array[i + 1] != 0)
        read_card_rec_from_arduino[i] = 16 * getNum(inp_from_arduino_array[i]) + getNum(inp_from_arduino_array[i + 1]);
      if (inp_from_arduino_array[i] != 0 && inp_from_arduino_array[i + 1] == 0)
        read_card_rec_from_arduino[i] = 16 * getNum(inp_from_arduino_array[i]);
      if (inp_from_arduino_array[i] == 0 && inp_from_arduino_array[i + 1] != 0)
        read_card_rec_from_arduino[i] = getNum(inp_from_arduino_array[i + 1]);
      if (inp_from_arduino_array[i] == 0 && inp_from_arduino_array[i + 1] == 0)
        read_card_rec_from_arduino[i] = 0;
    } else {
      if (inp_from_arduino_array[i] != 0 && inp_from_arduino_array[i + 1] != 0)
        read_card_rec_from_arduino[i / 2] = 16 * getNum(inp_from_arduino_array[i]) + getNum(inp_from_arduino_array[i + 1]);
      if (inp_from_arduino_array[i] != 0 && inp_from_arduino_array[i + 1] == 0)
        read_card_rec_from_arduino[i / 2] = 16 * getNum(inp_from_arduino_array[i]);
      if (inp_from_arduino_array[i] == 0 && inp_from_arduino_array[i + 1] != 0)
        read_card_rec_from_arduino[i / 2] = getNum(inp_from_arduino_array[i + 1]);
      if (inp_from_arduino_array[i] == 0 && inp_from_arduino_array[i + 1] == 0)
        read_card_rec_from_arduino[i / 2] = 0;
    }
  }
}

void press_any_key_to_continue_lock_screen() {
  bool break_the_loop = false;
  while (break_the_loop == false) {
    display_letters_with_shifting_background();
    code = keyboard.available();
    if (code > 0) {
      code = keyboard.read();
      code = keymap.remapKey(code);
      if (code > 0) {
        break_the_loop = true;
      }
    }
    delayMicroseconds(400);
  }
}

void get_input_from_arduino_uno_key_to_canc(){
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
    delayMicroseconds(400);
      code = keyboard.available();
      if (code > 0) {
        code = keyboard.read();
        code = keymap.remapKey(code);
        if (code > 0) {
          if ((code & 0xFF)) {

            if ((code & 0xFF) == 27) { // Esc
              cont_to_next_step = false;
              inByte = '\n';
              break;
            }
          }

        }
      }
      delayMicroseconds(400);
  }
  mySerial.end();
  if (cont_to_next_step != false){
    int inp_from_arduino_len = inp_from_arduino.length() + 1;
    char inp_from_arduino_array[inp_from_arduino_len];
    inp_from_arduino.toCharArray(inp_from_arduino_array, inp_from_arduino_len);
    for (int i = 0; i < 8; i += 2) {
      if (i == 0) {
        if (inp_from_arduino_array[i] != 0 && inp_from_arduino_array[i + 1] != 0)
          read_card_rec_from_arduino[i] = 16 * getNum(inp_from_arduino_array[i]) + getNum(inp_from_arduino_array[i + 1]);
        if (inp_from_arduino_array[i] != 0 && inp_from_arduino_array[i + 1] == 0)
          read_card_rec_from_arduino[i] = 16 * getNum(inp_from_arduino_array[i]);
        if (inp_from_arduino_array[i] == 0 && inp_from_arduino_array[i + 1] != 0)
          read_card_rec_from_arduino[i] = getNum(inp_from_arduino_array[i + 1]);
        if (inp_from_arduino_array[i] == 0 && inp_from_arduino_array[i + 1] == 0)
          read_card_rec_from_arduino[i] = 0;
      } else {
        if (inp_from_arduino_array[i] != 0 && inp_from_arduino_array[i + 1] != 0)
          read_card_rec_from_arduino[i / 2] = 16 * getNum(inp_from_arduino_array[i]) + getNum(inp_from_arduino_array[i + 1]);
        if (inp_from_arduino_array[i] != 0 && inp_from_arduino_array[i + 1] == 0)
          read_card_rec_from_arduino[i / 2] = 16 * getNum(inp_from_arduino_array[i]);
        if (inp_from_arduino_array[i] == 0 && inp_from_arduino_array[i + 1] != 0)
          read_card_rec_from_arduino[i / 2] = getNum(inp_from_arduino_array[i + 1]);
        if (inp_from_arduino_array[i] == 0 && inp_from_arduino_array[i + 1] == 0)
          read_card_rec_from_arduino[i / 2] = 0;
      }
    }
  }
}

// 3DES + AES + Blowfish + Serpent in CBC Mode(Below)

void split_by_ten(char plntxt[], int k, int str_len) {
  byte res[] = {
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0
  };
  byte res2[8] = {
    0,
    0
  };

  for (int i = 0; i < 8; i++) {
    if (i + k > str_len - 1)
      break;
    res[i] = byte(plntxt[i + k]);
  }

  for (int i = 0; i < 2; i++) {
    if (i + 8 + k > str_len - 1)
      break;
    res2[i] = byte(plntxt[i + 8 + k]);
  }

  for (int i = 0; i < 8; i++) {
    res[i] ^= array_for_CBC_mode[i];
  }

  for (int i = 0; i < 2; i++) {
    res2[i] ^= array_for_CBC_mode[i + 8];
  }

  encrypt_with_tdes(res, res2);
}

void encrypt_iv_for_tdes_aes_blwfsh_serp() {
  byte res[] = {
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0
  };
  byte res2[8] = {
    0,
    0
  };

  for (int i = 0; i < 10; i++) {
    array_for_CBC_mode[i] = get_rnd_val();
  }

  for (int i = 0; i < 8; i++) {
    res[i] = array_for_CBC_mode[i];
  }

  for (int i = 0; i < 2; i++) {
    res2[i] = array_for_CBC_mode[i + 8];
  }

  encrypt_with_tdes(res, res2);
}

void encrypt_with_tdes(byte res[], byte res2[]) {

  for (int i = 2; i < 8; i++) {
    res2[i] = get_rnd_val();
  }

  byte out[8];
  byte out2[8];
  des.tripleEncrypt(out, res, des_key);
  incr_des_key();
  des.tripleEncrypt(out2, res2, des_key);
  incr_des_key();

  char t_aes[16];

  for (int i = 0; i < 8; i++) {
    int b = out[i];
    t_aes[i] = char(b);
  }

  for (int i = 0; i < 8; i++) {
    int b = out2[i];
    t_aes[i + 8] = char(b);
  }

  encrypt_with_AES(t_aes);
}

void encrypt_with_AES(char t_enc[]) {
  uint8_t text[16] = {
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0
  };
  for (int i = 0; i < 16; i++) {
    int c = int(t_enc[i]);
    text[i] = c;
  }
  uint8_t cipher_text[16] = {
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0
  };
  uint32_t AES_key_bit[3] = {
    128,
    192,
    256
  };
  int i = 0;
  aes_context ctx;
  aes_set_key( & ctx, AES_key, AES_key_bit[m]);
  aes_encrypt_block( & ctx, cipher_text, text);
  /*
  for (int i=0; i<16; i++) {
    if(cipher_text[i]<16)
      Serial.print("0");
    Serial.print(cipher_text[i],HEX);
  }
  Serial.println();
  */
  incr_AES_key();
  unsigned char first_eight[8];
  unsigned char second_eight[8];
  for (int i = 0; i < 8; i++) {
    first_eight[i] = (unsigned char) cipher_text[i];
    second_eight[i] = (unsigned char) cipher_text[i + 8];
  }
  encrypt_with_Blowfish(first_eight, false);
  encrypt_with_Blowfish(second_eight, true);
  encrypt_with_serpent();
}

void encrypt_with_Blowfish(unsigned char inp[], bool lrside) {
  unsigned char plt[8];
  for (int i = 0; i < 8; i++)
    plt[i] = inp[i];
  blowfish.SetKey(Blwfsh_key, sizeof(Blwfsh_key));
  blowfish.Encrypt(plt, plt, sizeof(plt));
  String encrypted_with_blowfish;
  for (int i = 0; i < 8; i++) {
    if (lrside == false)
      pass_to_serp[i] = int(plt[i]);
    if (lrside == true)
      pass_to_serp[i + 8] = int(plt[i]);
  }
  incr_Blwfsh_key();
}

void encrypt_with_serpent() {
  uint8_t ct1[32], pt1[32], key[64];
  int plen, clen, b, j;
  serpent_key skey;
  serpent_blk ct2;
  uint32_t * p;

  for (b = 0; b < 1; b++) {
    hex2bin(key);

    // set key
    memset( & skey, 0, sizeof(skey));
    p = (uint32_t * ) & skey.x[0][0];

    serpent_setkey( & skey, key);

    for (int i = 0; i < 16; i++) {
      ct2.b[i] = pass_to_serp[i];
    }
    serpent_encrypt(ct2.b, & skey, SERPENT_ENCRYPT);
    incr_serp_key();
    /*
    for (int i = 0; i < 16; i++) {
      if (ct2.b[i] < 16)
        Serial.print("0");
      Serial.print(ct2.b[i], HEX);
    }
    */
    for (int i = 0; i < 16; i++) {
      if (decract > 0) {
        if (i < 10) {
          array_for_CBC_mode[i] = byte(int(ct2.b[i]));
        }
      }
      if (ct2.b[i] < 16)
        dec_st += "0";
      dec_st += String(ct2.b[i], HEX);
    }
    decract++;
  }
}

void split_for_decryption(char ct[], int ct_len, int p) {
  int br = false;
  byte res[] = {
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0
  };
  byte prev_res[] = {
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0
  };
  for (int i = 0; i < 32; i += 2) {
    if (i + p > ct_len - 1) {
      br = true;
      break;
    }
    if (i == 0) {
      if (ct[i + p] != 0 && ct[i + p + 1] != 0)
        res[i] = 16 * getNum(ct[i + p]) + getNum(ct[i + p + 1]);
      if (ct[i + p] != 0 && ct[i + p + 1] == 0)
        res[i] = 16 * getNum(ct[i + p]);
      if (ct[i + p] == 0 && ct[i + p + 1] != 0)
        res[i] = getNum(ct[i + p + 1]);
      if (ct[i + p] == 0 && ct[i + p + 1] == 0)
        res[i] = 0;
    } else {
      if (ct[i + p] != 0 && ct[i + p + 1] != 0)
        res[i / 2] = 16 * getNum(ct[i + p]) + getNum(ct[i + p + 1]);
      if (ct[i + p] != 0 && ct[i + p + 1] == 0)
        res[i / 2] = 16 * getNum(ct[i + p]);
      if (ct[i + p] == 0 && ct[i + p + 1] != 0)
        res[i / 2] = getNum(ct[i + p + 1]);
      if (ct[i + p] == 0 && ct[i + p + 1] == 0)
        res[i / 2] = 0;
    }
  }

  for (int i = 0; i < 32; i += 2) {
    if (i + p - 32 > ct_len - 1) {
      br = true;
      break;
    }
    if (i == 0) {
      if (ct[i + p - 32] != 0 && ct[i + p - 32 + 1] != 0)
        prev_res[i] = 16 * getNum(ct[i + p - 32]) + getNum(ct[i + p - 32 + 1]);
      if (ct[i + p - 32] != 0 && ct[i + p - 32 + 1] == 0)
        prev_res[i] = 16 * getNum(ct[i + p - 32]);
      if (ct[i + p - 32] == 0 && ct[i + p - 32 + 1] != 0)
        prev_res[i] = getNum(ct[i + p - 32 + 1]);
      if (ct[i + p - 32] == 0 && ct[i + p - 32 + 1] == 0)
        prev_res[i] = 0;
    } else {
      if (ct[i + p - 32] != 0 && ct[i + p - 32 + 1] != 0)
        prev_res[i / 2] = 16 * getNum(ct[i + p - 32]) + getNum(ct[i + p - 32 + 1]);
      if (ct[i + p - 32] != 0 && ct[i + p - 32 + 1] == 0)
        prev_res[i / 2] = 16 * getNum(ct[i + p - 32]);
      if (ct[i + p - 32] == 0 && ct[i + p - 32 + 1] != 0)
        prev_res[i / 2] = getNum(ct[i + p - 32 + 1]);
      if (ct[i + p - 32] == 0 && ct[i + p - 32 + 1] == 0)
        prev_res[i / 2] = 0;
    }
  }

  if (br == false) {
    if (decract > 10) {
      for (int i = 0; i < 10; i++) {
        array_for_CBC_mode[i] = prev_res[i];
      }
    }
    uint8_t ct1[32], pt1[32], key[64];
    int plen, clen, i, j;
    serpent_key skey;
    serpent_blk ct2;
    uint32_t * p;

    for (i = 0; i < 1; i++) {
      hex2bin(key);

      // set key
      memset( & skey, 0, sizeof(skey));
      p = (uint32_t * ) & skey.x[0][0];

      serpent_setkey( & skey, key);

      for (int i = 0; i < 16; i++)
        ct2.b[i] = res[i];
      /*
      Serial.printf ("\n\n");
      for(int i = 0; i<16; i++){
      Serial.printf("%x", ct2.b[i]);
      Serial.printf(" ");
      */
    }
    //Serial.printf("\n");
    serpent_encrypt(ct2.b, & skey, SERPENT_DECRYPT);
    incr_serp_key();
    unsigned char lh[8];
    unsigned char rh[8];
    for (int i = 0; i < 8; i++) {
      lh[i] = (unsigned char) int(ct2.b[i]);
      rh[i] = (unsigned char) int(ct2.b[i + 8]);
    }
    blowfish.SetKey(Blwfsh_key, sizeof(Blwfsh_key));
    blowfish.Decrypt(lh, lh, sizeof(lh));
    incr_Blwfsh_key();
    blowfish.SetKey(Blwfsh_key, sizeof(Blwfsh_key));
    blowfish.Decrypt(rh, rh, sizeof(rh));
    incr_Blwfsh_key();
    uint8_t ret_text[16] = {
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0
    };
    uint8_t cipher_text[16] = {
      0
    };
    for (int i = 0; i < 8; i++) {
      int c = int(lh[i]);
      cipher_text[i] = c;
    }
    for (int i = 0; i < 8; i++) {
      int c = int(rh[i]);
      cipher_text[i + 8] = c;
    }
    /*
    for (int i=0; i<16; i++) {
      if(cipher_text[i]<16)
        Serial.print("0");
      Serial.print(cipher_text[i],HEX);
    }
    Serial.println();
    */
    uint32_t AES_key_bit[3] = {
      128,
      192,
      256
    };
    aes_context ctx;
    aes_set_key( & ctx, AES_key, AES_key_bit[m]);
    aes_decrypt_block( & ctx, ret_text, cipher_text);
    incr_AES_key();

    byte res[8];
    byte res2[8];

    for (int i = 0; i < 8; i++) {
      res[i] = int(ret_text[i]);
      res2[i] = int(ret_text[i + 8]);
    }

    byte out[8];
    byte out2[8];
    des.tripleDecrypt(out, res, des_key);
    incr_des_key();
    des.tripleDecrypt(out2, res2, des_key);
    incr_des_key();
    /*
        Serial.println();
        for (int i=0; i<8; i++) {
          if(out[i]<8)
            Serial.print("0");
          Serial.print(out[i],HEX);
        }

        for (int i=0; i<8; i++) {
          if(out2[i]<8)
            Serial.print("0");
          Serial.print(out[i],HEX);
        }
        Serial.println();
    */

    if (decract > 2) {
      for (int i = 0; i < 8; i++) {
        out[i] ^= array_for_CBC_mode[i];
      }

      for (int i = 0; i < 2; i++) {
        out2[i] ^= array_for_CBC_mode[i + 8];
      }

      if (decrypt_tag == false) {

        for (i = 0; i < 8; ++i) {
          if (out[i] > 0)
            dec_st += char(out[i]);
        }

        for (i = 0; i < 2; ++i) {
          if (out2[i] > 0)
            dec_st += char(out2[i]);
        }

      } else {
        for (i = 0; i < 8; ++i) {
          if (out[i] < 0x10)
            dec_tag += "0";
          dec_tag += String(out[i], HEX);
        }

        for (i = 0; i < 2; ++i) {
          if (out2[i] < 0x10)
            dec_tag += "0";
          dec_tag += String(out2[i], HEX);
        }
      }
    }

    if (decract == -1) {
      for (i = 0; i < 8; ++i) {
        array_for_CBC_mode[i] = out[i];
      }

      for (i = 0; i < 2; ++i) {
        array_for_CBC_mode[i + 8] = out2[i];;
      }
    }
    decract++;
  }
}

void encrypt_hash_with_tdes_aes_blf_srp(String input) {
  back_keys();
  clear_variables();
  encrypt_iv_for_tdes_aes_blwfsh_serp();
  SHA256HMAC hmac(hmackey, sizeof(hmackey));
  int str_len = input.length() + 1;
  char input_arr[str_len];
  input.toCharArray(input_arr, str_len);
  hmac.doUpdate(input_arr);
  byte authCode[SHA256HMAC_SIZE];
  hmac.doFinal(authCode);
  int p = 0;
  char hmacchar[30];
  for (int i = 0; i < 30; i++) {
    hmacchar[i] = char(authCode[i]);
  }

  for (int i = 0; i < 3; i++) {
    split_by_ten(hmacchar, p, 100);
    p += 10;
  }
  rest_keys();
}

void encrypt_with_TDES_AES_Blowfish_Serp(String input) {
  back_keys();
  clear_variables();
  encrypt_iv_for_tdes_aes_blwfsh_serp();
  int str_len = input.length() + 1;
  char input_arr[str_len];
  input.toCharArray(input_arr, str_len);
  int p = 0;
  while (str_len > p + 1) {
    split_by_ten(input_arr, p, str_len);
    p += 10;
  }
  rest_keys();
}

void decrypt_with_TDES_AES_Blowfish_Serp(String ct) {
  back_keys();
  clear_variables();
  decrypt_tag = false;
  int ct_len = ct.length() + 1;
  char ct_array[ct_len];
  ct.toCharArray(ct_array, ct_len);
  int ext = 0;
  decract = -1;
  while (ct_len > ext) {
    split_for_decryption(ct_array, ct_len, 0 + ext);
    ext += 32;
    decract += 10;
  }
  rest_keys();
}

void decrypt_tag_with_TDES_AES_Blowfish_Serp(String ct) {
  back_keys();
  clear_variables();
  decrypt_tag = true;
  int ct_len = ct.length() + 1;
  char ct_array[ct_len];
  ct.toCharArray(ct_array, ct_len);
  int ext = 0;
  decract = -1;
  while (ct_len > ext) {
    split_for_decryption(ct_array, ct_len, 0 + ext);
    ext += 32;
    decract += 10;
  }
  rest_keys();
}

void encrypt_string_with_tdes_aes_blf_srp(String input) {
  encrypt_with_TDES_AES_Blowfish_Serp(input);
  String td_aes_bl_srp_ciphertext = dec_st;
  encrypt_hash_with_tdes_aes_blf_srp(input);
  dec_st += td_aes_bl_srp_ciphertext;
}

void decrypt_string_with_TDES_AES_Blowfish_Serp(String ct) {
  back_keys();
  clear_variables();
  decrypt_tag = true;
  int ct_len = ct.length() + 1;
  char ct_array[ct_len];
  ct.toCharArray(ct_array, ct_len);
  int ext = 0;
  decract = -1;
  for (int i = 0; i < 128; i += 32) {
    split_for_decryption(ct_array, ct_len, 0 + ext);
    ext += 32;
    decract += 10;
  }
  rest_keys();

  back_keys();
  dec_st = "";
  decrypt_tag = false;
  int ct_len1 = ct.length() + 1;
  char ct_array1[ct_len1];
  ct.toCharArray(ct_array1, ct_len1);
  ext = 128;
  decract = -1;
  while (ct_len1 > ext) {
    split_for_decryption(ct_array1, ct_len1, 0 + ext);
    ext += 32;
    decract += 10;
  }
  rest_keys();
}

// 3DES + AES + Blowfish + Serpent in CBC Mode (Above)

bool verify_integrity() {
  int str_lentg = dec_st.length() + 1;
  char char_arraytg[str_lentg];
  dec_st.toCharArray(char_arraytg, str_lentg);
  SHA256HMAC hmac(hmackey, sizeof(hmackey));
  hmac.doUpdate(char_arraytg);
  byte authCode[SHA256HMAC_SIZE];
  hmac.doFinal(authCode);
  String res_hash;

  for (byte i = 0; i < SHA256HMAC_SIZE - 2; i++) {
    if (authCode[i] < 0x10) {
      res_hash += 0;
    } {
      res_hash += String(authCode[i], HEX);
    }
  }
  /*
  Serial.println(dec_st);
  Serial.println(dec_tag);
  Serial.println(res_hash);
  */
  return dec_tag.equals(res_hash);
}

void set_stuff_for_input(String blue_inscr) {
  curr_key = 65;
  tft.fillScreen(0x0000);
  tft.setTextSize(2);
  tft.setTextColor(0xffff);
  tft.setCursor(2, 0);
  tft.print("Char'");
  tft.setCursor(74, 0);
  tft.print("'");
  disp();
  tft.setCursor(0, 24);
  tft.setTextSize(2);
  tft.setTextColor(current_inact_clr);
  tft.print(blue_inscr);
  tft.fillRect(312, 0, 8, 240, current_inact_clr);
  tft.setTextColor(0x07e0);
  tft.setCursor(216, 0);
  tft.print("ASCII:");
}

void check_bounds_and_change_char() {
  if (curr_key < 32)
    curr_key = 126;

  if (curr_key > 126)
    curr_key = 32;

  if (keyboard_input.length() > 0)
    curr_key = keyboard_input.charAt(keyboard_input.length() - 1);
}

void disp() {
  //gfx->fillScreen(0x0000);
  tft.setTextSize(2);
  tft.setTextColor(0xffff);
  tft.fillRect(62, 0, 10, 16, 0x0000);
  tft.setCursor(62, 0);
  tft.print(char(curr_key));
  tft.fillRect(288, 0, 22, 14, 0x0000);
  tft.setCursor(288, 0);
  String hexstr;
  if (curr_key < 16)
    hexstr += 0;
  hexstr += String(curr_key, HEX);
  hexstr.toUpperCase();
  tft.setTextColor(0x07e0);
  tft.print(hexstr);
  tft.setTextColor(0xffff);
  tft.setTextSize(2);
  tft.setCursor(0, 48);
  tft.print(keyboard_input);
}

void disp_stars() {
  //gfx->fillScreen(0x0000);
  tft.setTextSize(2);
  tft.setTextColor(0xffff);
  tft.fillRect(62, 0, 10, 16, 0x0000);
  tft.setCursor(62, 0);
  tft.print(char(curr_key));
  tft.fillRect(288, 0, 22, 14, 0x0000);
  tft.setCursor(288, 0);
  String hexstr;
  if (curr_key < 16)
    hexstr += 0;
  hexstr += String(curr_key, HEX);
  hexstr.toUpperCase();
  tft.setTextColor(0x07e0);
  tft.print(hexstr);
  int plnt = keyboard_input.length();
  String stars = "";
  for (int i = 0; i < plnt; i++) {
    stars += "*";
  }
  tft.setTextColor(0xffff);
  tft.setTextSize(2);
  tft.setCursor(0, 48);
  tft.print(stars);
}

byte get_PS2_keyb_input(){
  byte data_to_ret = 0;
    code = keyboard.available();
    if (code > 0) {
      code = keyboard.read();
      if (code == 277) { // Leftwards Arrow
       data_to_ret = 129;
     }
     if (code == 278) { // Rightwards Arrow
       data_to_ret = 130;
     }
     if (code == 279) { // Upwards Arrow
       data_to_ret = 131;
     }
     if (code == 280) { // Downwards Arrow
       data_to_ret = 132;
     }
      code = keymap.remapKey(code);
      if (code > 0) {
        if ((code & 0xFF)) {

          if ((code & 0xFF) == 27) { // Esc
            data_to_ret = 27;
          } else if ((code & 0xFF) == 13) { // Enter
            data_to_ret = 13;
          } else if ((code & 0xFF) == 8) { // Backspace
            data_to_ret = 8;
          } else {
            data_to_ret = code & 0xFF;
          }
        }

      }
    }

    delayMicroseconds(400);
    return data_to_ret;
}

void keyb_input() {
  finish_input = false;
  while (finish_input == false) {

    if (curr_key < 32)
      curr_key = 126;

    if (curr_key > 126)
      curr_key = 32;

    code = keyboard.available();
    if (code > 0) {
      code = keyboard.read();
      code = keymap.remapKey(code);
      if (code > 0) {
        if ((code & 0xFF)) {

          if ((code & 0xFF) == 27) { // Esc
            act = false;
            finish_input = true;
          } else if ((code & 0xFF) == 13) { // Enter
            finish_input = true;
          } else if ((code & 0xFF) == 8) { // Backspace
            if (keyboard_input.length() > 0)
              keyboard_input.remove(keyboard_input.length() - 1, 1);
            //Serial.println(keyboard_input);
            tft.fillRect(0, 48, 312, 192, 0x0000);
            //Serial.println(keyboard_input);
            check_bounds_and_change_char();
            disp();
          } else {
            keyboard_input += char(code & 0xFF);
            check_bounds_and_change_char();
            disp();
          }
        }

      }
    }

    delayMicroseconds(400);
  }
}

void star_keyb_input() {
  finish_input = false;
  while (finish_input == false) {

    if (curr_key < 32)
      curr_key = 126;

    if (curr_key > 126)
      curr_key = 32;

    code = keyboard.available();
    if (code > 0) {
      code = keyboard.read();
      code = keymap.remapKey(code);
      if (code > 0) {
        if ((code & 0xFF)) {
          if ((code & 0xFF) == 27) { // Esc
            act = false;
            finish_input = true;
          } else if ((code & 0xFF) == 13) { // Enter
            finish_input = true;
          } else if ((code & 0xFF) == 8) { // Backspace
            if (keyboard_input.length() > 0)
              keyboard_input.remove(keyboard_input.length() - 1, 1);
            //Serial.println(keyboard_input);
            tft.fillRect(0, 48, 312, 192, 0x0000);
            //Serial.println(keyboard_input);
            check_bounds_and_change_char();
            disp_stars();
          } else {
            keyboard_input += char(code & 0xFF);
            check_bounds_and_change_char();
            disp_stars();
          }
        }

      }
    }
    delayMicroseconds(400);
  }
}

// Functions that work with files on SD card (Below)

String read_file(String filename){
  if(Firebase.getString(fbdo, filename.c_str())){
    return (fbdo.to<String>());
  }
  else
    return "-1";
}

void write_to_file_with_overwrite(String filename, String content){
  if (!Firebase.set(fbdo, filename.c_str(), content.c_str())){
    tft.fillScreen(0x0000);
    tft.setTextColor(0xf800);
    tft.setCursor(0, 0);
    tft.print("Failed To Create File!");
    delay(2000);
    tft.fillScreen(0x0000);    
  }
}

void delete_file(String filename){
  if(!Firebase.deleteNode(fbdo, filename.c_str())){
    tft.fillScreen(0x0000);
    tft.setTextColor(0xf800);
    tft.setCursor(0, 0);
    tft.print("Failed To Delete File!");
    delay(2000);
    tft.fillScreen(0x0000);
  }
}

// Functions that work with files on SD card (Above)

void press_any_key_to_continue() {
  bool break_the_loop = false;
  while (break_the_loop == false) {
    code = keyboard.available();
    if (code > 0) {
      code = keyboard.read();
      code = keymap.remapKey(code);
      if (code > 0) {
        if ((code & 0xFF)) {
          break_the_loop = true;
        }

      }
    }
    delayMicroseconds(400);
  }
}

void continue_to_unlock() {
  keyboard_input = "";
  if (read_file("/kppass").equals("-1"))
    set_pass();
  else
    unlock_khadashpay();
  return;
}

void set_pass() {
  clear_variables();
  tft.fillScreen(0x0000);
  tft.setTextColor(0xffff);
  tft.setTextSize(1);
  set_stuff_for_input("Set Master Password");
  keyb_input();
  tft.fillScreen(0x0000);
  tft.setTextSize(2);
  tft.setTextColor(0xffff);
  disp_centered_text("Setting Master Password", 65);
  disp_centered_text("Please wait", 85);
  disp_centered_text("for a while", 105);
  //Serial.println(keyboard_input);
  String bck = keyboard_input;
  modify_keys();
  keyboard_input = bck;
  set_psswd();
  tft.fillScreen(0x0000);
  tft.setTextSize(2);
  tft.setTextColor(0xffff);
  disp_centered_text("Master Password Set", 65);
  disp_centered_text("Successfully", 85);
  disp_centered_text("Press Any Key To Set", 105);
  disp_centered_text("Operator Password", 125);
  press_any_key_to_continue();
  clear_variables();
  set_stuff_for_input("Set Operator Password");
  keyb_input();
  String read_keyboard_input = keyboard_input;
  tft.fillScreen(0x0000);
  tft.setTextSize(2);
  tft.setTextColor(0xffff);
  disp_centered_text("Setting Operator Password", 65);
  disp_centered_text("Please wait", 85);
  disp_centered_text("for a while", 105);
  back_keys();
  clear_variables();
  encrypt_hash_with_tdes_aes_blf_srp(read_keyboard_input);
  rest_keys();
  //Serial.println(dec_st);
  write_to_file_with_overwrite("/oprpsswd", dec_st);
  tft.fillScreen(0x0000);
  tft.setTextSize(2);
  tft.setTextColor(0xffff);
  disp_centered_text("Operator Password Set", 65);
  disp_centered_text("Successfully", 85);
  disp_centered_text("Press Any Key", 105);
  disp_centered_text("To Continue", 125);
  press_any_key_to_continue();
  call_main_menu();
  return;
}

void set_psswd() {
  int str_len = keyboard_input.length() + 1;
  char input_arr[str_len];
  keyboard_input.toCharArray(input_arr, str_len);
  std::string str = "";
  if (str_len > 1) {
    for (int i = 0; i < str_len - 1; i++) {
      str += input_arr[i];
    }
  }
  String h = sha512(str).c_str();
  for (int i = 0; i < numofkincr * 2; i++) {
    int str_len1 = h.length() + 1;
    char input_arr1[str_len1];
    h.toCharArray(input_arr1, str_len1);
    std::string str1 = "";
    if (str_len1 > 1) {
      for (int i = 0; i < str_len1 - 1; i++) {
        str1 += input_arr1[i];
      }
    }
    h = sha512(str1).c_str();
    delay(1);
    if (i == ((numofkincr * 2) / 3)) {
      for (int j = 0; j < 8; j++) {
        h += String(read_cards[j], HEX);
      }
    }
    if (i == numofkincr) {
      for (int j = 0; j < 8; j++) {
        h += String(read_cards[j + 8], HEX);
      }
    }
    if (i == ((numofkincr * 3) / 2)) {
      for (int j = 0; j < 16; j++) {
        h += String(read_cards[j], HEX);
      }
    }
  }
  //Serial.println();
  //Serial.println(h);
  back_keys();
  dec_st = "";
  encrypt_hash_with_tdes_aes_blf_srp(h);
  rest_keys();
  //Serial.println(dec_st);

  write_to_file_with_overwrite("/kppass", dec_st);
}

void modify_keys() {
  keyboard_input += kderalgs;
  int str_len = keyboard_input.length() + 1;
  char input_arr[str_len];
  keyboard_input.toCharArray(input_arr, str_len);
  std::string str = "";
  if (str_len > 1) {
    for (int i = 0; i < str_len - 1; i++) {
      str += input_arr[i];
    }
  }
  String h = sha512(str).c_str();
  for (int i = 0; i < numofkincr; i++) {
    int str_len1 = h.length() + 1;
    char input_arr1[str_len1];
    h.toCharArray(input_arr1, str_len1);
    std::string str1 = "";
    if (str_len1 > 1) {
      for (int i = 0; i < str_len1 - 1; i++) {
        str1 += input_arr1[i];
      }
    }
    h = sha512(str1).c_str();
    delay(1);
    if (i == numofkincr / 2) {
      for (int j = 0; j < 16; j++) {
        h += String(read_cards[j], HEX);
      }
    }
  }
  //Serial.println(h);
  int h_len = h.length() + 1;
  char h_array[h_len];
  h.toCharArray(h_array, h_len);
  byte res[64];
  for (int i = 0; i < 128; i += 2) {
    if (i == 0) {
      if (h_array[i] != 0 && h_array[i + 1] != 0)
        res[i] = 16 * getNum(h_array[i]) + getNum(h_array[i + 1]);
      if (h_array[i] != 0 && h_array[i + 1] == 0)
        res[i] = 16 * getNum(h_array[i]);
      if (h_array[i] == 0 && h_array[i + 1] != 0)
        res[i] = getNum(h_array[i + 1]);
      if (h_array[i] == 0 && h_array[i + 1] == 0)
        res[i] = 0;
    } else {
      if (h_array[i] != 0 && h_array[i + 1] != 0)
        res[i / 2] = 16 * getNum(h_array[i]) + getNum(h_array[i + 1]);
      if (h_array[i] != 0 && h_array[i + 1] == 0)
        res[i / 2] = 16 * getNum(h_array[i]);
      if (h_array[i] == 0 && h_array[i + 1] != 0)
        res[i / 2] = getNum(h_array[i + 1]);
      if (h_array[i] == 0 && h_array[i + 1] == 0)
        res[i / 2] = 0;
    }
  }
  for (int i = 0; i < 13; i++) {
    hmackey[i] = res[i];
  }
  des_key[9] = res[13];
  des_key[16] = (unsigned char) res[31];
  des_key[17] = (unsigned char) res[32];
  des_key[18] = (unsigned char) res[33];
  serp_key[12] = int(res[34]);
  serp_key[14] = int(res[35]);
  for (int i = 0; i < 9; i++) {
    Blwfsh_key[i] = (unsigned char) res[i + 14];
  }
  for (int i = 0; i < 3; i++) {
    des_key[i] = (unsigned char) res[i + 23];
  }
  for (int i = 0; i < 5; i++) {
    hmackey[i + 13] = int(res[i + 26]);
  }
  for (int i = 0; i < 10; i++) {
    AES_key[i] = int(res[i + 36]);
  }
  for (int i = 0; i < 9; i++) {
    serp_key[i] = int(res[i + 46]);
  }
  for (int i = 0; i < 4; i++) {
    hmackey[i + 18] = res[i + 55];
    des_key[i + 3] = (unsigned char) res[i + 59];
  }
  for (int i = 0; i < 5; i++) {
    second_AES_key[i] = ((int(res[i + 31]) * int(res[i + 11])) + int(res[50])) % 256;
  }
}

void unlock_khadashpay() {
  clear_variables();
  tft.fillScreen(0x0000);
  tft.setTextColor(0xffff);
  tft.setTextSize(2);
  set_stuff_for_input("Enter Master Password");
  star_keyb_input();
  tft.fillScreen(0x0000);
  tft.setTextSize(2);
  disp_centered_text("Unlocking", 45);
  disp_centered_text("KhadashPay", 65);
  disp_centered_text("Please wait", 85);
  disp_centered_text("for a while", 105);
  //Serial.println(keyboard_input);
  String bck = keyboard_input;
  modify_keys();
  keyboard_input = bck;
  bool next_act = hash_psswd();
  clear_variables();
  tft.fillScreen(0x0000);
  if (next_act == true) {
    tft.setTextSize(2);
    disp_centered_text("KhadashPay", 45);
    disp_centered_text("unlocked", 65);
    disp_centered_text("successfully", 85);
    disp_centered_text("Press any key", 105);
    disp_centered_text("to continue", 125);
    press_any_key_to_continue();
    call_main_menu();
    return;
  } else {
    tft.setTextSize(2);
    tft.setTextColor(five_six_five_red_color);
    disp_centered_text("Wrong Password!", 65);
    tft.setTextColor(0xffff);
    disp_centered_text("Please reboot", 100);
    disp_centered_text("the device", 120);
    disp_centered_text("and try again", 140);
    for (;;)
      delay(1000);
  }
}

bool hash_psswd() {
  int str_len = keyboard_input.length() + 1;
  char input_arr[str_len];
  keyboard_input.toCharArray(input_arr, str_len);
  std::string str = "";
  if (str_len > 1) {
    for (int i = 0; i < str_len - 1; i++) {
      str += input_arr[i];
    }
  }
  String h = sha512(str).c_str();
  for (int i = 0; i < numofkincr * 2; i++) {
    int str_len1 = h.length() + 1;
    char input_arr1[str_len1];
    h.toCharArray(input_arr1, str_len1);
    std::string str1 = "";
    if (str_len1 > 1) {
      for (int i = 0; i < str_len1 - 1; i++) {
        str1 += input_arr1[i];
      }
    }
    h = sha512(str1).c_str();
    delay(1);
    if (i == ((numofkincr * 2) / 3)) {
      for (int j = 0; j < 8; j++) {
        h += String(read_cards[j], HEX);
      }
    }
    if (i == numofkincr) {
      for (int j = 0; j < 8; j++) {
        h += String(read_cards[j + 8], HEX);
      }
    }
    if (i == ((numofkincr * 3) / 2)) {
      for (int j = 0; j < 16; j++) {
        h += String(read_cards[j], HEX);
      }
    }
  }
  //Serial.println();
  //Serial.println(h);

  SHA256HMAC hmac(hmackey, sizeof(hmackey));
  int h_len1 = h.length() + 1;
  char h_arr[h_len1];
  h.toCharArray(h_arr, h_len1);
  hmac.doUpdate(h_arr);
  byte authCode[SHA256HMAC_SIZE];
  hmac.doFinal(authCode);
  int p = 0;
  char hmacchar[30];
  for (int i = 0; i < 30; i++) {
    hmacchar[i] = char(authCode[i]);
  }

  String res_hash;
  for (int i = 0; i < 30; i++) {
    if (hmacchar[i] < 0x10)
      res_hash += "0";
    res_hash += String(hmacchar[i], HEX);
  }
  /*
    Serial.println();

      for (int i = 0; i < 30; i++) {
        if (hmacchar[i] < 16)
          Serial.print("0");
        Serial.print(hmacchar[i], HEX);
      }
    Serial.println();
  */
  back_keys();
  clear_variables();
  //Serial.println(read_file("/kppass"));
  decrypt_tag_with_TDES_AES_Blowfish_Serp(read_file("/kppass"));
  //Serial.println(dec_tag);
  return dec_tag.equals(res_hash);
}

void disp_centered_text(String text, int h) {
  if (text.length() < 27)
    tft.drawCentreString(text, 160, h, 1);
  else {
    tft.setCursor(0, h);
    tft.println(text);
  }
}

void disp_centered_text_b_w(String text, int h) {
  tft.setTextColor(0x0882);
  tft.drawCentreString(text, 160, h - 1, 1);
  tft.drawCentreString(text, 160, h + 1, 1);
  tft.drawCentreString(text, 159, h, 1);
  tft.drawCentreString(text, 161, h, 1);
  tft.setTextColor(0xf7de);
  tft.drawCentreString(text, 160, h, 1);
}

int chosen_lock_screen;
unsigned int k;

void display_letters_with_shifting_background(){
  if (chosen_lock_screen == 0){
    for (int i = 0; i < 312; i++){
      for (int j = 0; j < 61; j++){
        if (khadash_pay_icon[i][j] == 1)
          mvng_bc.drawPixel(i, j, Beer_Sheva[(i + 4 + k)%320][j+120]);
      }
    }
  }

  if (chosen_lock_screen == 1){
    for (int i = 0; i < 312; i++){
      for (int j = 0; j < 61; j++){
        if (khadash_pay_icon[i][j] == 1)
          mvng_bc.drawPixel(i, j, Dallas[(i + 4 + k)%320][j+120]);
      }
    }
  }

  if (chosen_lock_screen == 2){
    for (int i = 0; i < 312; i++){
      for (int j = 0; j < 61; j++){
        if (khadash_pay_icon[i][j] == 1)
          mvng_bc.drawPixel(i, j, Frankfurt[(i + 4 + k)%320][j+120]);
      }
    }
  }

  if (chosen_lock_screen == 3){
    for (int i = 0; i < 312; i++){
      for (int j = 0; j < 61; j++){
        if (khadash_pay_icon[i][j] == 1)
          mvng_bc.drawPixel(i, j, Kansas_City[(i + 4 + k)%320][j+120]);
      }
    }
  }

  if (chosen_lock_screen == 4){
    for (int i = 0; i < 312; i++){
      for (int j = 0; j < 61; j++){
        if (khadash_pay_icon[i][j] == 1)
          mvng_bc.drawPixel(i, j, Kuwait_City[(i + 4 + k)%320][j+120]);
      }
    }
  }

  if (chosen_lock_screen == 5){
    for (int i = 0; i < 312; i++){
      for (int j = 0; j < 61; j++){
        if (khadash_pay_icon[i][j] == 1)
          mvng_bc.drawPixel(i, j, London[(i + 4 + k)%320][j+120]);
      }
    }
  }

  if (chosen_lock_screen == 6){
    for (int i = 0; i < 312; i++){
      for (int j = 0; j < 61; j++){
        if (khadash_pay_icon[i][j] == 1)
          mvng_bc.drawPixel(i, j, Minneapolis[(i + 4 + k)%320][j+120]);
      }
    }
  }

  if (chosen_lock_screen == 7){
    for (int i = 0; i < 312; i++){
      for (int j = 0; j < 61; j++){
        if (khadash_pay_icon[i][j] == 1)
          mvng_bc.drawPixel(i, j, Pittsburgh[(i + 4 + k)%320][j+120]);
      }
    }
  }

  if (chosen_lock_screen == 8){
    for (int i = 0; i < 312; i++){
      for (int j = 0; j < 61; j++){
        if (khadash_pay_icon[i][j] == 1)
          mvng_bc.drawPixel(i, j, Tel_Aviv[(i + 4 + k)%320][j+120]);
      }
    }
  }

  mvng_bc.pushSprite(4, 10, TFT_TRANSPARENT);
  k++;
}

void display_lock_screen() {
  if (chosen_lock_screen == 0){
    for (int i = 0; i < 320; i++){
      for (int j = 0; j < 240; j++){
        tft.drawPixel(i, j, Beer_Sheva[i][j]);
      }
    }
  }

  if (chosen_lock_screen == 1){
    for (int i = 0; i < 320; i++){
      for (int j = 0; j < 240; j++){
        tft.drawPixel(i, j, Dallas[i][j]);
      }
    }
  }

  if (chosen_lock_screen == 2){
    for (int i = 0; i < 320; i++){
      for (int j = 0; j < 240; j++){
        tft.drawPixel(i, j, Frankfurt[i][j]);
      }
    }
  }

  if (chosen_lock_screen == 3){
    for (int i = 0; i < 320; i++){
      for (int j = 0; j < 240; j++){
        tft.drawPixel(i, j, Kansas_City[i][j]);
      }
    }
  }

  if (chosen_lock_screen == 4){
    for (int i = 0; i < 320; i++){
      for (int j = 0; j < 240; j++){
        tft.drawPixel(i, j, Kuwait_City[i][j]);
      }
    }
  }

  if (chosen_lock_screen == 5){
    for (int i = 0; i < 320; i++){
      for (int j = 0; j < 240; j++){
        tft.drawPixel(i, j, London[i][j]);
      }
    }
  }

  if (chosen_lock_screen == 6){
    for (int i = 0; i < 320; i++){
      for (int j = 0; j < 240; j++){
        tft.drawPixel(i, j, Minneapolis[i][j]);
      }
    }
  }

  if (chosen_lock_screen == 7){
    for (int i = 0; i < 320; i++){
      for (int j = 0; j < 240; j++){
        tft.drawPixel(i, j, Pittsburgh[i][j]);
      }
    }
  }

  if (chosen_lock_screen == 8){
    for (int i = 0; i < 320; i++){
      for (int j = 0; j < 240; j++){
        tft.drawPixel(i, j, Tel_Aviv[i][j]);
      }
    }
  }

  delay(500);

  for (int i = 0; i < 312; i++) {
    for (int j = 0; j < 61; j++) {
      if (khadash_pay_per[i][j] == 1)
        tft.drawPixel(i + 4, j + 10, 0xf7de);
    }
  }

  mvng_bc.createSprite(312, 61);
  mvng_bc.setColorDepth(16);
  mvng_bc.fillSprite(TFT_TRANSPARENT);
}

void lock_scr_without_rfid() {
  chosen_lock_screen = esp_random() % 9;
  display_lock_screen();
  tft.setTextSize(2);
  tft.setTextColor(0xf7de);
  disp_centered_text_b_w("Press Any Key", 214);
  mvng_bc.fillSprite(TFT_TRANSPARENT);
  k = 0;
  press_any_key_to_continue_lock_screen();
  //mvng_bc.deleteSprite();
}

// Menu (Below)
void call_main_menu() {
  menu_pos = 0;
  tft.fillScreen(0x0000);
  for (int i = 0; i < 312; i++) {
    for (int j = 0; j < 61; j++) {
      if (khadash_pay_per[i][j] == 1 || khadash_pay_icon[i][j] == 1)
        tft.drawPixel(i + 4, j + 10, 0xf7de);
    }
  }
  disp_menu();
}

void disp_menu() {
  tft.setTextSize(2);
  if (menu_pos == 0) {
    tft.setTextColor(0xffff);
    disp_centered_text("Make A Sale", 100);
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Put Money In", 120);
    disp_centered_text("New Account", 140);
    disp_centered_text("View Balance", 160);
    disp_centered_text("Other Options", 180);
  }
  if (menu_pos == 1) {
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Make A Sale", 100);
    tft.setTextColor(0xffff);
    disp_centered_text("Put Money In", 120);
    tft.setTextColor(current_inact_clr);
    disp_centered_text("New Account", 140);
    disp_centered_text("View Balance", 160);
    disp_centered_text("Other Options", 180);
  }
  if (menu_pos == 2) {
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Make A Sale", 100);
    disp_centered_text("Put Money In", 120);
    tft.setTextColor(0xffff);
    disp_centered_text("New Account", 140);
    tft.setTextColor(current_inact_clr);
    disp_centered_text("View Balance", 160);
    disp_centered_text("Other Options", 180);
  }
  if (menu_pos == 3) {
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Make A Sale", 100);
    disp_centered_text("Put Money In", 120);
    disp_centered_text("New Account", 140);
    tft.setTextColor(0xffff);
    disp_centered_text("View Balance", 160);
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Other Options", 180);
  }
  if (menu_pos == 4) {
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Make A Sale", 100);
    disp_centered_text("Put Money In", 120);
    disp_centered_text("New Account", 140);
    disp_centered_text("View Balance", 160);
    tft.setTextColor(0xffff);
    disp_centered_text("Other Options", 180);
  }
}

void lock_screen_keyboard() {
  chosen_lock_screen = esp_random() % 9;
  display_lock_screen();
  tft.setTextSize(1);
  tft.setTextColor(0xf7de);
  disp_centered_text_b_w("sourceforge.net/projects/khadashpay-firebase-edition/", 218);
  disp_centered_text_b_w("github.com/Northstrix/KhadashPay-Firebase-Edition", 230);
  bool break_loop = false;
  mvng_bc.fillSprite(TFT_TRANSPARENT);
  k = 0;
  while (break_loop == false) {
    code = keyboard.available();
    if (code > 0) {
      code = keyboard.read();
      code = keymap.remapKey(code);
      if (code > 0) {
        if ((code & 0xFF)) {
          break_loop = true;
        }

      }
    }
    display_letters_with_shifting_background();
  }
  call_main_menu();
  //mvng_bc.deleteSprite();
}
// Menu (Above)

void tab_to_print_rec_to_serial_terminal() {
  bool break_the_loop = false;
  while (break_the_loop == false) {
    if (keyboard.available()) {
      c = keyboard.read();
      if (c == 285) {
        act = true;
        break_the_loop = true;
      } else
        break_the_loop = true;
    }
    delayMicroseconds(400);
  }
}

void disp_button_designation() {
  tft.setTextSize(1);
  tft.setTextColor(0x07e0);
  tft.setCursor(0, 232);
  tft.print("'Enter' - continue                     ");
  tft.setTextColor(five_six_five_red_color);
  tft.print("'Esc' - cancel");
}

void disp_button_designation_for_del() {
  tft.setTextSize(1);
  tft.setTextColor(five_six_five_red_color);
  tft.setCursor(0, 232);
  tft.print("'Enter' - continue                     ");
  tft.setTextColor(0x07e0);
  tft.print("'Esc' - cancel");
}

void disp_paste_smth_inscr(String what_to_pst) {
  tft.fillScreen(0x0000);
  tft.setTextColor(0xffff);
  tft.setTextSize(2);
  disp_centered_text("Paste " + what_to_pst + " to", 30);
  disp_centered_text("the Serial Terminal", 50);
  tft.setTextColor(five_six_five_red_color);
  disp_centered_text("Press any key", 200);
  disp_centered_text("to cancel", 220);
}

void disp_paste_cphrt_inscr() {
  tft.fillScreen(0x0000);
  tft.setTextColor(0xffff);
  tft.setTextSize(2);
  disp_centered_text("Paste Ciphertext to", 30);
  disp_centered_text("the Serial Terminal", 50);
  tft.setTextColor(five_six_five_red_color);
  disp_centered_text("Press any key", 200);
  disp_centered_text("to cancel", 220);
}

void disp_plt_on_tft(bool intgrt) {
  tft.fillScreen(0x0000);
  tft.setTextColor(current_inact_clr);
  tft.setTextSize(1);
  disp_centered_text("Plaintext", 10);
  if (intgrt == true)
    tft.setTextColor(0xffff);
  else {
    tft.setTextColor(five_six_five_red_color);
    disp_centered_text("Integrity Verification failed!!!", 232);
  }
  disp_centered_text(dec_st, 30);
}

void call_oth_opt_menu() {
  tft.fillScreen(0x0000);
  for (int i = 0; i < 312; i++) {
    for (int j = 0; j < 61; j++) {
      if (khadash_pay_per[i][j] == 1 || khadash_pay_icon[i][j] == 1)
        tft.drawPixel(i + 4, j + 10, 0xf7de);
    }
  }
  disp_oth_opt_menu();
}

void disp_oth_opt_menu() {
  tft.setTextSize(2);
  byte sdown = 90;
  if (menu_pos == 0) {
    tft.setTextColor(0xffff);
    disp_centered_text("Logins", sdown + 10);
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Credit Cards", sdown + 30);
    disp_centered_text("Notes", sdown + 50);
    disp_centered_text("Phone Numbers", sdown + 70);
  }
  if (menu_pos == 1) {
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Logins", sdown + 10);
    tft.setTextColor(0xffff);
    disp_centered_text("Credit Cards", sdown + 30);
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Notes", sdown + 50);
    disp_centered_text("Phone Numbers", sdown + 70);
  }
  if (menu_pos == 2) {
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Logins", sdown + 10);
    disp_centered_text("Credit Cards", sdown + 30);
    tft.setTextColor(0xffff);
    disp_centered_text("Notes", sdown + 50);
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Phone Numbers", sdown + 70);
  }
  if (menu_pos == 3) {
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Logins", sdown + 10);
    disp_centered_text("Credit Cards", sdown + 30);
    disp_centered_text("Notes", sdown + 50);
    tft.setTextColor(0xffff);
    disp_centered_text("Phone Numbers", sdown + 70);
  }
}

void action_for_oth_opt() {
  tft.fillScreen(0x0000);
  menu_pos = 0;
  gen_r = true;
  call_oth_opt_menu();
  disp_button_designation();
  bool cont_to_next_el = false;
  while (cont_to_next_el == false) {
    for (int i = 0; i < 312; i++) {
      for (int j = 0; j < 61; j++) {
        if (khadash_pay_icon[i][j] == 1)
          mvng_bc.drawPixel(i, j, London[(i + 4 + k) % 320][j + 98]);
      }
    }
    mvng_bc.pushSprite(4, 10, TFT_TRANSPARENT);
    if (keyboard.available()) {
      c = keyboard.read();
      if (c == 279 || c == 56)
        menu_pos--;

      if (c == 280 || c == 48)
        menu_pos++;

      if (menu_pos < 0)
        menu_pos = 3;

      if (menu_pos > 3)
        menu_pos = 0;

      if ((c & 0xFF) == 30) {
        if (menu_pos == 0) {
          action_for_data_in_flash("Logins Menu", 0);
          cont_to_next_el = true;
        }

        if (menu_pos == 1) {
          action_for_data_in_flash("Credit Cards Menu", 1);
          cont_to_next_el = true;
        }

        if (menu_pos == 2) {
          action_for_data_in_flash("Notes Menu", 2);
          cont_to_next_el = true;
        }

        if (menu_pos == 3) {
          action_for_data_in_flash("Phone Numbers Menu", 3);
          cont_to_next_el = true;
        }
      }

      if ((c & 0xFF) == 27) {
        cont_to_next_el = true;
      }
      disp_oth_opt_menu();

    }
    delayMicroseconds(400);
    k++;
  }
  call_main_menu();
}

void where_to_print_plaintext_menu(int curr_pos) {
  tft.setTextSize(2);
  byte sdown = 60;
  if (curr_pos == 0) {
    tft.setTextColor(0xffff);
    disp_centered_text("Display", sdown + 10);
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Serial Terminal", sdown + 30);
  }
  if (curr_pos == 1) {
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Display", sdown + 10);
    tft.setTextColor(0xffff);
    disp_centered_text("Serial Terminal", sdown + 30);
  }
}

void where_to_print_plaintext() {
  tft.fillScreen(0x0000);
  tft.setTextSize(2);
  tft.setTextColor(current_inact_clr);
  disp_centered_text("Where to print plaintext?", 10);
  curr_key = 0;
  where_to_print_plaintext_menu(curr_key);
  disp_button_designation();
  bool cont_to_next_el = false;
  while (cont_to_next_el == false) {
    if (keyboard.available()) {
      c = keyboard.read();

      if (c == 279 || c == 56)
        curr_key--;

      if (c == 280 || c == 48)
        curr_key++;

      if (curr_key < 0)
        curr_key = 1;

      if (curr_key > 1)
        curr_key = 0;

      if ((c & 0xFF) == 30) {

        if (curr_key == 0) {
          decr_TDES_AES_BLF_Serp(true);
          cont_to_next_el = true;
        }

        if (curr_key == 1) {
          decr_TDES_AES_BLF_Serp(false);
          cont_to_next_el = true;
        }
      }
      if ((c & 0xFF) == 27) {
        cont_to_next_el = true;
      }
      where_to_print_plaintext_menu(curr_key);

    }
  }
  call_main_menu();
}

void input_source_for_encr_algs_menu(int curr_pos) {
  tft.setTextSize(2);
  byte sdown = 60;
  if (curr_pos == 0) {
    tft.setTextColor(0xffff);
    disp_centered_text("PS/2 Keyboard", sdown + 10);
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Serial Terminal", sdown + 30);
  }
  if (curr_pos == 1) {
    tft.setTextColor(current_inact_clr);
    disp_centered_text("PS/2 Keyboard", sdown + 10);
    tft.setTextColor(0xffff);
    disp_centered_text("Serial Terminal", sdown + 30);
  }
}

void input_source_for_encr_algs() {
  tft.fillScreen(0x0000);
  tft.setTextSize(2);
  tft.setTextColor(current_inact_clr);
  disp_centered_text("Choose Input Source", 10);
  curr_key = 0;
  input_source_for_encr_algs_menu(curr_key);
  disp_button_designation();
  bool cont_to_next_el = false;
  while (cont_to_next_el == false) {
    if (keyboard.available()) {
      c = keyboard.read();

      if (c == 279 || c == 56)
        curr_key--;

      if (c == 280 || c == 48)
        curr_key++;

      if (curr_key < 0)
        curr_key = 1;

      if (curr_key > 1)
        curr_key = 0;

      if ((c & 0xFF) == 30) {

        if (curr_key == 0) {
          encr_TDES_AES_BLF_Serp();
          cont_to_next_el = true;
        }

        if (curr_key == 1) {
          encr_TDES_AES_BLF_Serp_from_Serial();
          cont_to_next_el = true;
        }

      }
      if ((c & 0xFF) == 27) {
        cont_to_next_el = true;
      }
      input_source_for_encr_algs_menu(curr_key);

    }
  }
  call_main_menu();
}

void encr_TDES_AES_BLF_Serp() {
  act = true;
  clear_variables();
  tft.fillScreen(0x0000);
  tft.setTextColor(0xffff);
  tft.setCursor(0, 20);
  tft.setTextSize(1);
  set_stuff_for_input("Enter text to encrypt");
  keyb_input();
  tft.fillScreen(0x0000);
  tft.setTextSize(1);
  tft.setTextColor(0xffff);
  tft.setCursor(0, 0);
  tft.print("Encrypting the text...");
  tft.setCursor(0, 10);
  tft.print("Please wait for a while.");
  if (act == true) {
    encrypt_string_with_tdes_aes_blf_srp(keyboard_input);
    Serial.println("\nCiphertext");
    Serial.println(dec_st);
  }
  clear_variables();
  call_main_menu();
  return;
}

void encr_TDES_AES_BLF_Serp_from_Serial() {
  bool cont_to_next = false;
  while (cont_to_next == false) {
    disp_paste_smth_inscr("Plaintext");
    Serial.println("\nPaste the string you want to encrypt here:");
    bool canc_op = false;
    while (!Serial.available()) {
      if (keyboard.available()) {
        c = keyboard.read();

        canc_op = true;
        break;

      }
      delayMicroseconds(400);
    }
    if (canc_op == true)
      break;
    tft.fillScreen(0x0000);
    tft.setTextSize(1);
    tft.setTextColor(0xffff);
    tft.setCursor(0, 0);
    tft.print("Encrypting the text...");
    tft.setCursor(0, 10);
    tft.print("Please wait for a while.");
    String plt = Serial.readString();
    encrypt_string_with_tdes_aes_blf_srp(plt);
    Serial.println("\nCiphertext");
    Serial.println(dec_st);
    cont_to_next = true;
    clear_variables();
    call_main_menu();
    return;
  }
}

void decr_TDES_AES_BLF_Serp(bool print_plt_on_disp_or_serial) {
  bool cont_to_next = false;
  while (cont_to_next == false) {
    disp_paste_cphrt_inscr();
    Serial.println("\nPaste the ciphertext here:");
    bool canc_op = false;
    while (!Serial.available()) {
      if (keyboard.available()) {
        c = keyboard.read();

        canc_op = true;
        break;

      }
      delayMicroseconds(400);
    }
    if (canc_op == true)
      break;
    tft.fillScreen(0x0000);
    tft.setTextSize(1);
    tft.setTextColor(0xffff);
    tft.setCursor(0, 0);
    tft.print("Decrypting the text...");
    tft.setCursor(0, 10);
    tft.print("Please wait for a while.");
    String ct = Serial.readString();
    decrypt_string_with_TDES_AES_Blowfish_Serp(ct);
    bool plt_integr = verify_integrity();
    if (print_plt_on_disp_or_serial == true) {
      disp_plt_on_tft(plt_integr);
      clear_variables();
      press_any_key_to_continue();
    } else {
      Serial.println("Plaintext:");
      Serial.println(dec_st);
      if (plt_integr == true)
        Serial.println("Integrity verified successfully!");
      else
        Serial.println("Integrity Verification failed!!!");
    }
    clear_variables();
    call_main_menu();
    return;
  }
}

void action_for_data_in_flash_menu(int curr_pos) {
  tft.setTextSize(2);
  byte sdown = 60;
  if (curr_pos == 0) {
    tft.setTextColor(0xffff);
    disp_centered_text("Add", sdown + 10);
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Edit", sdown + 30);
    disp_centered_text("Delete", sdown + 50);
    disp_centered_text("View", sdown + 70);
  }
  if (curr_pos == 1) {
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Add", sdown + 10);
    tft.setTextColor(0xffff);
    disp_centered_text("Edit", sdown + 30);
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Delete", sdown + 50);
    disp_centered_text("View", sdown + 70);
  }
  if (curr_pos == 2) {
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Add", sdown + 10);
    disp_centered_text("Edit", sdown + 30);
    tft.setTextColor(0xffff);
    disp_centered_text("Delete", sdown + 50);
    tft.setTextColor(current_inact_clr);
    disp_centered_text("View", sdown + 70);
  }
  if (curr_pos == 3) {
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Add", sdown + 10);
    disp_centered_text("Edit", sdown + 30);
    disp_centered_text("Delete", sdown + 50);
    tft.setTextColor(0xffff);
    disp_centered_text("View", sdown + 70);
  }
}

void action_for_data_in_flash(String menu_title, byte record_type) {
  tft.fillScreen(0x0000);
  tft.setTextSize(2);
  tft.setTextColor(current_inact_clr);
  disp_centered_text(menu_title, 10);
  curr_key = 0;

  action_for_data_in_flash_menu(curr_key);
  disp_button_designation();
  bool cont_to_next = false;
  while (cont_to_next == false) {
    byte input_data = get_PS2_keyb_input();
    if (input_data > 0) {

      if (input_data == 129 || input_data == 131)
        curr_key--;

      if (input_data == 130 || input_data == 132)
        curr_key++;

      if (curr_key < 0)
        curr_key = 3;

      if (curr_key > 3)
        curr_key = 0;

      if (input_data == 13 || input_data == 133) {
        if (curr_key == 0) {
          if (record_type == 0)
            select_login(0);
          if (record_type == 1)
            select_credit_card(0);
          if (record_type == 2)
            select_note(0);
          if (record_type == 3)
            select_phone_number(0);
          cont_to_next = true;
        }

        if (curr_key == 1 && cont_to_next == false) {
          if (record_type == 0)
            select_login(1);
          if (record_type == 1)
            select_credit_card(1);
          if (record_type == 2)
            select_note(1);
          if (record_type == 3)
            select_phone_number(1);
          cont_to_next = true;
        }

        if (curr_key == 2 && cont_to_next == false) {
          if (record_type == 0)
            select_login(2);
          if (record_type == 1)
            select_credit_card(2);
          if (record_type == 2)
            select_note(2);
          if (record_type == 3)
            select_phone_number(2);
          cont_to_next = true;
        }

        if (curr_key == 3 && cont_to_next == false) {
          if (record_type == 0)
            select_login(3);
          if (record_type == 1)
            select_credit_card(3);
          if (record_type == 2)
            select_note(3);
          if (record_type == 3)
            select_phone_number(3);
          cont_to_next = true;
        }
      }
      if (input_data == 8 || input_data == 27) {
        cont_to_next = true;
      }
      action_for_data_in_flash_menu(curr_key);

    }
  }
  call_main_menu();
}

void input_source_for_data_in_flash_menu(int curr_pos) {
  tft.setTextSize(2);
  byte sdown = 60;
  if (curr_pos == 0) {
    tft.setTextColor(0xffff);
    disp_centered_text("PS/2 Keyboard", sdown + 10);
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Serial Terminal", sdown + 30);
  }
  if (curr_pos == 1) {
    tft.setTextColor(current_inact_clr);
    disp_centered_text("PS/2 Keyboard", sdown + 10);
    tft.setTextColor(0xffff);
    disp_centered_text("Serial Terminal", sdown + 30);
  }
}

byte input_source_for_data_in_flash() {
  byte inpsrc = 0;
  tft.fillScreen(0x0000);
  tft.setTextSize(2);
  tft.setTextColor(current_inact_clr);
  disp_centered_text("Choose Input Source", 10);
  curr_key = 0;
  input_source_for_data_in_flash_menu(curr_key);
  disp_button_designation();
  bool cont_to_next_el = false;
  while (cont_to_next_el == false) {
    if (keyboard.available()) {
      c = keyboard.read();

      if (c == 279 || c == 56)
        curr_key--;

      if (c == 280 || c == 48)
        curr_key++;

      if (curr_key < 0)
        curr_key = 1;

      if (curr_key > 1)
        curr_key = 0;

      if ((c & 0xFF) == 30) {
        if (curr_key == 0) {
          inpsrc = 1;
        }

        if (curr_key == 1) {
          inpsrc = 2;
        }
        cont_to_next_el = true;
        break;
      }
      if ((c & 0xFF) == 27) {
        cont_to_next_el = true;
        break;
      }
      input_source_for_data_in_flash_menu(curr_key);

    }
  }
  return inpsrc;
}

void select_login(byte what_to_do_with_it) {
  // 0 - Add login
  // 1 - Edit login
  // 2 - Delete login
  // 3 - View login
  delay(DELAY_FOR_SLOTS);
  curr_key = 1;

  header_for_select_login(what_to_do_with_it);
  display_title_from_login_without_integrity_verification();
  bool continue_to_next = false;
  while (continue_to_next == false) {
    byte input_data = get_PS2_keyb_input();
    if (input_data > 0) {

      if (input_data == 130)
        curr_key++;

      if (input_data == 129)
        curr_key--;

      if (curr_key < 1)
        curr_key = MAX_NUM_OF_RECS;

      if (curr_key > MAX_NUM_OF_RECS)
        curr_key = 1;

      if (input_data == 13 || input_data == 133) { // Enter
        int chsn_slot = curr_key;
        if (what_to_do_with_it == 0 && continue_to_next == false) {
          continue_to_next = true;
          add_login_from_nint_controller(chsn_slot);
        }
        if (what_to_do_with_it == 1 && continue_to_next == false) {
          continue_to_next = true;
          tft.fillScreen(0x0000);
          tft.setTextSize(1);
          tft.setTextColor(0xffff);
          tft.setCursor(0, 0);
          tft.print("Decrypting the record...");
          tft.setCursor(0, 10);
          tft.print("Please wait for a while.");
          edit_login_from_nint_controller(chsn_slot);
        }
        if (what_to_do_with_it == 2 && continue_to_next == false) {
          continue_to_next = true;
          delete_login(chsn_slot);
        }
        if (what_to_do_with_it == 3 && continue_to_next == false) {
          continue_to_next = true;
          tft.fillScreen(0x0000);
          tft.setTextSize(1);
          tft.setTextColor(0xffff);
          tft.setCursor(0, 0);
          tft.print("Decrypting the record...");
          tft.setCursor(0, 10);
          tft.print("Please wait for a while.");
          view_login(chsn_slot);
        }
        continue_to_next = true;
        break;
      }

      if (input_data == 8 || input_data == 27) {
        call_main_menu();
        continue_to_next = true;
        break;
      }
      delay(DELAY_FOR_SLOTS);
      header_for_select_login(what_to_do_with_it);
      display_title_from_login_without_integrity_verification();
    }
    delayMicroseconds(500);
  }
  return;
}

void header_for_select_login(byte what_to_do_with_it) {
  tft.fillScreen(0x0000);
  tft.setTextSize(2);
  if (what_to_do_with_it == 0) {
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Add Login to Slot " + String(curr_key) + "/" + String(MAX_NUM_OF_RECS), 5);
    disp_button_designation();
  }
  if (what_to_do_with_it == 1) {
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Edit Login " + String(curr_key) + "/" + String(MAX_NUM_OF_RECS), 5);
    disp_button_designation();
  }
  if (what_to_do_with_it == 2) {
    tft.setTextColor(five_six_five_red_color);
    disp_centered_text("Delete Login " + String(curr_key) + "/" + String(MAX_NUM_OF_RECS), 5);
    disp_button_designation_for_del();
  }
  if (what_to_do_with_it == 3) {
    tft.setTextColor(current_inact_clr);
    disp_centered_text("View Login " + String(curr_key) + "/" + String(MAX_NUM_OF_RECS), 5);
    disp_button_designation();
  }
}

void display_title_from_login_without_integrity_verification() {
  tft.setTextSize(2);
  String encrypted_title = read_file("/L" + String(curr_key) + "_ttl");
  if (encrypted_title == "-1") {
    tft.setTextColor(0x07e0);
    disp_centered_text("Empty", 35);
  } else {
    clear_variables();
    decrypt_tag = false;
    decrypt_with_TDES_AES_Blowfish_Serp(encrypted_title);
    tft.setTextColor(0xffff);
    disp_centered_text(dec_st, 35);
  }
}

void add_login_from_nint_controller(int chsn_slot) {
  enter_title_for_login(chsn_slot);
  clear_variables();
  call_main_menu();
  return;
}

void enter_title_for_login(int chsn_slot) {
  act = true;
  clear_variables();
  set_stuff_for_input("Enter Title");
  keyb_input();
  if (act == true) {
    enter_username_for_login(chsn_slot, keyboard_input);
  }
  return;
}

void enter_username_for_login(int chsn_slot, String entered_title) {
  act = true;
  clear_variables();
  set_stuff_for_input("Enter Username");
  keyb_input();
  if (act == true) {
    enter_password_for_login(chsn_slot, entered_title, keyboard_input);
  }
  return;
}

void enter_password_for_login(int chsn_slot, String entered_title, String entered_username) {
  act = true;
  clear_variables();
  set_stuff_for_input("Enter Password");
  keyb_input();
  if (act == true) {
    enter_website_for_login(chsn_slot, entered_title, entered_username, keyboard_input);
  }
  return;
}

void enter_website_for_login(int chsn_slot, String entered_title, String entered_username, String entered_password) {
  act = true;
  clear_variables();
  set_stuff_for_input("Enter Website");
  keyb_input();
  if (act == true) {
    write_login_to_flash(chsn_slot, entered_title, entered_username, entered_password, keyboard_input);
  }
  return;
}

void write_login_to_flash(int chsn_slot, String entered_title, String entered_username, String entered_password, String entered_website) {
  /*
  Serial.println();
  Serial.println(chsn_slot);
  Serial.println(entered_title);
  Serial.println(entered_username);
  Serial.println(entered_password);
  Serial.println(entered_website);
  */
  tft.fillScreen(0x0000);
  tft.setTextSize(1);
  tft.setTextColor(0xffff);
  disp_centered_text("Adding Login To The Slot N" + String(chsn_slot) + "...", 5);
  disp_centered_text("Please wait for a while.", 17);
  clear_variables();
  encrypt_with_TDES_AES_Blowfish_Serp(entered_title);
  delay(DELAY_FOR_SLOTS);
  write_to_file_with_overwrite("/L" + String(chsn_slot) + "_ttl", dec_st);
  clear_variables();
  encrypt_with_TDES_AES_Blowfish_Serp(entered_username);
  delay(DELAY_FOR_SLOTS);
  write_to_file_with_overwrite("/L" + String(chsn_slot) + "_usn", dec_st);
  clear_variables();
  encrypt_with_TDES_AES_Blowfish_Serp(entered_password);
  delay(DELAY_FOR_SLOTS);
  write_to_file_with_overwrite("/L" + String(chsn_slot) + "_psw", dec_st);
  clear_variables();
  encrypt_with_TDES_AES_Blowfish_Serp(entered_website);
  delay(DELAY_FOR_SLOTS);
  write_to_file_with_overwrite("/L" + String(chsn_slot) + "_wbs", dec_st);
  clear_variables();
  encrypt_hash_with_tdes_aes_blf_srp(entered_title + entered_username + entered_password + entered_website);
  delay(DELAY_FOR_SLOTS);
  write_to_file_with_overwrite("/L" + String(chsn_slot) + "_tag", dec_st);
  return;
}

void update_login_and_tag(int chsn_slot, String new_password) {
  tft.fillScreen(0x0000);
  tft.setTextSize(1);
  tft.setTextColor(0xffff);
  tft.setCursor(0, 0);
  tft.print("Editing Login In The Slot N" + String(chsn_slot) + "...");
  tft.setCursor(0, 10);
  tft.print("Please wait for a while.");

  clear_variables();
  encrypt_with_TDES_AES_Blowfish_Serp(new_password);
  delay(DELAY_FOR_SLOTS);
  write_to_file_with_overwrite("/L" + String(chsn_slot) + "_psw", dec_st);

  clear_variables();
  decrypt_with_TDES_AES_Blowfish_Serp(read_file("/L" + String(chsn_slot) + "_ttl"));
  String decrypted_title = dec_st;
  clear_variables();
  decrypt_with_TDES_AES_Blowfish_Serp(read_file("/L" + String(chsn_slot) + "_usn"));
  String decrypted_username = dec_st;
  clear_variables();
  decrypt_with_TDES_AES_Blowfish_Serp(read_file("/L" + String(chsn_slot) + "_wbs"));
  String decrypted_website = dec_st;

  clear_variables();
  encrypt_hash_with_tdes_aes_blf_srp(decrypted_title + decrypted_username + new_password + decrypted_website);
  delay(DELAY_FOR_SLOTS);
  write_to_file_with_overwrite("/L" + String(chsn_slot) + "_tag", dec_st);
  return;
}

void edit_login_from_nint_controller(int chsn_slot) {
  if (read_file("/L" + String(chsn_slot) + "_psw") == "-1") {
    tft.fillScreen(0x0000);
    tft.setTextColor(0x07e0);
    tft.setTextSize(2);
    disp_centered_text("The Slot N" + String(chsn_slot) + " is Empty", 5);
    tft.setTextColor(0xffff);
    tft.setTextSize(1);
    disp_centered_text("Press any key to return to the main menu", 232);
    press_any_key_to_continue();
  } else {
    clear_variables();
    decrypt_with_TDES_AES_Blowfish_Serp(read_file("/L" + String(chsn_slot) + "_psw"));
    String old_password = dec_st;
    act = true;
    clear_variables();
    set_stuff_for_input("Edit Password");
    keyboard_input = old_password;
    disp();
    keyb_input();
    if (act == true) {
      update_login_and_tag(chsn_slot, keyboard_input);
    }
  }
  return;
}

void delete_login(int chsn_slot) {
  tft.fillScreen(0x0000);
  tft.setTextSize(1);
  tft.setTextColor(0xffff);
  tft.setCursor(0, 0);
  tft.print("Deleting Login From The Slot N" + String(chsn_slot) + "...");
  tft.setCursor(0, 10);
  tft.print("Please wait for a while.");
  delete_file("/L" + String(chsn_slot) + "_tag");
  delete_file("/L" + String(chsn_slot) + "_ttl");
  delete_file("/L" + String(chsn_slot) + "_usn");
  delete_file("/L" + String(chsn_slot) + "_psw");
  delete_file("/L" + String(chsn_slot) + "_wbs");
  clear_variables();
  call_main_menu();
  return;
}

void view_login(int chsn_slot) {
  if (read_file("/L" + String(chsn_slot) + "_ttl") == "-1") {
    tft.fillScreen(0x0000);
    tft.setTextColor(0x07e0);
    tft.setTextSize(2);
    disp_centered_text("The Slot N" + String(chsn_slot) + " is Empty", 5);
    tft.setTextColor(0xffff);
    tft.setTextSize(1);
    disp_centered_text("Press any key to return to the main menu", 232);
    press_any_key_to_continue();
  } else {
    clear_variables();
    decrypt_with_TDES_AES_Blowfish_Serp(read_file("/L" + String(chsn_slot) + "_ttl"));
    String decrypted_title = dec_st;
    clear_variables();
    decrypt_with_TDES_AES_Blowfish_Serp(read_file("/L" + String(chsn_slot) + "_usn"));
    String decrypted_username = dec_st;
    clear_variables();
    decrypt_with_TDES_AES_Blowfish_Serp(read_file("/L" + String(chsn_slot) + "_psw"));
    String decrypted_password = dec_st;
    clear_variables();
    decrypt_with_TDES_AES_Blowfish_Serp(read_file("/L" + String(chsn_slot) + "_wbs"));
    String decrypted_website = dec_st;
    clear_variables();
    decrypt_tag_with_TDES_AES_Blowfish_Serp(read_file("/L" + String(chsn_slot) + "_tag"));
    dec_st = decrypted_title + decrypted_username + decrypted_password + decrypted_website;
    bool login_integrity = verify_integrity();

    if (login_integrity == true) {
      tft.fillScreen(0x0000);
      tft.setTextSize(2);
      tft.setCursor(0, 5);
      tft.setTextColor(current_inact_clr);
      tft.print("Title:");
      tft.setTextColor(0xffff);
      tft.println(decrypted_title);
      tft.setTextColor(current_inact_clr);
      tft.print("Username:");
      tft.setTextColor(0xffff);
      tft.println(decrypted_username);
      tft.setTextColor(current_inact_clr);
      tft.print("Password:");
      tft.setTextColor(0xffff);
      tft.println(decrypted_password);
      tft.setTextColor(current_inact_clr);
      tft.print("Website:");
      tft.setTextColor(0xffff);
      tft.println(decrypted_website);
      tft.setTextSize(1);
      tft.fillRect(0, 230, 320, 14, 0x0000);
      tft.fillRect(312, 0, 8, 240, current_inact_clr);
      disp_centered_text("Integrity Verified Successfully!", 232);
    } else {
      tft.fillScreen(0x0000);
      tft.setTextSize(2);
      tft.setCursor(0, 5);
      tft.setTextColor(current_inact_clr);
      tft.print("Title:");
      tft.setTextColor(five_six_five_red_color);
      tft.println(decrypted_title);
      tft.setTextColor(current_inact_clr);
      tft.print("Username:");
      tft.setTextColor(five_six_five_red_color);
      tft.println(decrypted_username);
      tft.setTextColor(current_inact_clr);
      tft.print("Password:");
      tft.setTextColor(five_six_five_red_color);
      tft.println(decrypted_password);
      tft.setTextColor(current_inact_clr);
      tft.print("Website:");
      tft.setTextColor(five_six_five_red_color);
      tft.println(decrypted_website);
      tft.setTextSize(1);
      tft.fillRect(0, 230, 320, 14, 0x0000);
      tft.fillRect(312, 0, 8, 240, five_six_five_red_color);
      disp_centered_text("Integrity Verification Failed!", 232);
    }
    act = false;
    tab_to_print_rec_to_serial_terminal();
    if (act == true) {
      Serial.println();
      Serial.print("Title:\"");
      Serial.print(decrypted_title);
      Serial.println("\"");
      Serial.print("Username:\"");
      Serial.print(decrypted_username);
      Serial.println("\"");
      Serial.print("Password:\"");
      Serial.print(decrypted_password);
      Serial.println("\"");
      Serial.print("Website:\"");
      Serial.print(decrypted_website);
      Serial.println("\"");
      if (login_integrity == true) {
        Serial.println("Integrity Verified Successfully!\n");
      } else {
        Serial.println("Integrity Verification Failed!!!\n");
      }
    }
  }
}

// Functions for Logins (Above)

// Functions for Credit Cards (Below)

void select_credit_card(byte what_to_do_with_it) {
  // 0 - Add credit_card
  // 1 - Edit credit_card
  // 2 - Delete credit_card
  // 3 - View credit_card
  delay(DELAY_FOR_SLOTS);
  curr_key = 1;

  header_for_select_credit_card(what_to_do_with_it);
  display_title_from_credit_card_without_integrity_verification();
  bool continue_to_next = false;
  while (continue_to_next == false) {
    byte input_data = get_PS2_keyb_input();
    if (input_data > 0) {

      if (input_data == 130)
        curr_key++;

      if (input_data == 129)
        curr_key--;

      if (curr_key < 1)
        curr_key = MAX_NUM_OF_RECS;

      if (curr_key > MAX_NUM_OF_RECS)
        curr_key = 1;

      if (input_data == 13 || input_data == 133) { // Enter
        int chsn_slot = curr_key;
        if (what_to_do_with_it == 0 && continue_to_next == false) {
          continue_to_next = true;
          add_credit_card_from_nint_controller(chsn_slot);
        }
        if (what_to_do_with_it == 1 && continue_to_next == false) {
          continue_to_next = true;
          tft.fillScreen(0x0000);
          tft.setTextSize(1);
          tft.setTextColor(0xffff);
          tft.setCursor(0, 0);
          tft.print("Decrypting the record...");
          tft.setCursor(0, 10);
          tft.print("Please wait for a while.");
          edit_credit_card_from_nint_controller(chsn_slot);
        }
        if (what_to_do_with_it == 2 && continue_to_next == false) {
          continue_to_next = true;
          delete_credit_card(chsn_slot);
        }
        if (what_to_do_with_it == 3 && continue_to_next == false) {
          continue_to_next = true;
          tft.fillScreen(0x0000);
          tft.setTextSize(1);
          tft.setTextColor(0xffff);
          tft.setCursor(0, 0);
          tft.print("Decrypting the record...");
          tft.setCursor(0, 10);
          tft.print("Please wait for a while.");
          view_credit_card(chsn_slot);
        }
        continue_to_next = true;
        break;
      }

      if (input_data == 8 || input_data == 27) {
        call_main_menu();
        continue_to_next = true;
        break;
      }
      delay(DELAY_FOR_SLOTS);
      header_for_select_credit_card(what_to_do_with_it);
      display_title_from_credit_card_without_integrity_verification();
    }
    delayMicroseconds(500);
  }
  return;
}

void header_for_select_credit_card(byte what_to_do_with_it) {
  tft.fillScreen(0x0000);
  tft.setTextSize(2);
  if (what_to_do_with_it == 0) {
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Add Card to Slot " + String(curr_key) + "/" + String(MAX_NUM_OF_RECS), 5);
    disp_button_designation();
  }
  if (what_to_do_with_it == 1) {
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Edit Credit Card " + String(curr_key) + "/" + String(MAX_NUM_OF_RECS), 5);
    disp_button_designation();
  }
  if (what_to_do_with_it == 2) {
    tft.setTextColor(five_six_five_red_color);
    disp_centered_text("Delete Credit Card " + String(curr_key) + "/" + String(MAX_NUM_OF_RECS), 5);
    disp_button_designation_for_del();
  }
  if (what_to_do_with_it == 3) {
    tft.setTextColor(current_inact_clr);
    disp_centered_text("View Credit Card " + String(curr_key) + "/" + String(MAX_NUM_OF_RECS), 5);
    disp_button_designation();
  }
}

void display_title_from_credit_card_without_integrity_verification() {
  tft.setTextSize(2);
  String encrypted_title = read_file("/C" + String(curr_key) + "_ttl");
  if (encrypted_title == "-1") {
    tft.setTextColor(0x07e0);
    disp_centered_text("Empty", 35);
  } else {
    clear_variables();
    decrypt_tag = false;
    decrypt_with_TDES_AES_Blowfish_Serp(encrypted_title);
    tft.setTextColor(0xffff);
    disp_centered_text(dec_st, 35);
  }
}

void add_credit_card_from_nint_controller(int chsn_slot) {
  enter_title_for_credit_card(chsn_slot);
  clear_variables();
  call_main_menu();
  return;
}

void enter_title_for_credit_card(int chsn_slot) {
  act = true;
  clear_variables();
  set_stuff_for_input("Enter Title");
  keyb_input();
  if (act == true) {
    enter_cardholder_for_credit_card(chsn_slot, keyboard_input);
  }
  return;
}

void enter_cardholder_for_credit_card(int chsn_slot, String entered_title) {
  act = true;
  clear_variables();
  set_stuff_for_input("Enter Cardholder Name");
  keyb_input();
  if (act == true) {
    enter_card_number_for_credit_card(chsn_slot, entered_title, keyboard_input);
  }
  return;
}

void enter_card_number_for_credit_card(int chsn_slot, String entered_title, String entered_cardholder) {
  act = true;
  clear_variables();
  set_stuff_for_input("Enter Card Number");
  keyb_input();
  if (act == true) {
    enter_expiry_for_credit_card(chsn_slot, entered_title, entered_cardholder, keyboard_input);
  }
  return;
}

void enter_expiry_for_credit_card(int chsn_slot, String entered_title, String entered_cardholder, String entered_card_number) {
  act = true;
  clear_variables();
  set_stuff_for_input("Enter Expiration Date");
  keyb_input();
  if (act == true) {
    enter_cvn_for_credit_card(chsn_slot, entered_title, entered_cardholder, entered_card_number, keyboard_input);
  }
  return;
}

void enter_cvn_for_credit_card(int chsn_slot, String entered_title, String entered_cardholder, String entered_card_number, String entered_expiry) {
  act = true;
  clear_variables();
  set_stuff_for_input("Enter CVN");
  keyb_input();
  if (act == true) {
    enter_pin_for_credit_card(chsn_slot, entered_title, entered_cardholder, entered_card_number, entered_expiry, keyboard_input);
  }
  return;
}

void enter_pin_for_credit_card(int chsn_slot, String entered_title, String entered_cardholder, String entered_card_number, String entered_expiry, String entered_cvn) {
  act = true;
  clear_variables();
  set_stuff_for_input("Enter PIN");
  keyb_input();
  if (act == true) {
    enter_zip_code_for_credit_card(chsn_slot, entered_title, entered_cardholder, entered_card_number, entered_expiry, entered_cvn, keyboard_input);
  }
  return;
}

void enter_zip_code_for_credit_card(int chsn_slot, String entered_title, String entered_cardholder, String entered_card_number, String entered_expiry, String entered_cvn, String entered_pin) {
  act = true;
  clear_variables();
  set_stuff_for_input("Enter ZIP Code");
  keyb_input();
  if (act == true) {
    write_credit_card_to_flash(chsn_slot, entered_title, entered_cardholder, entered_card_number, entered_expiry, entered_cvn, entered_pin, keyboard_input);
  }
  return;
}

void write_credit_card_to_flash(int chsn_slot, String entered_title, String entered_cardholder, String entered_card_number, String entered_expiry, String entered_cvn, String entered_pin, String entered_zip_code) {
  /*
  Serial.println();
  Serial.println(chsn_slot);
  Serial.println(entered_title);
  Serial.println(entered_cardholder);
  Serial.println(entered_card_number);
  Serial.println(entered_expiry);
  */
  tft.fillScreen(0x0000);
  tft.setTextSize(1);
  tft.setTextColor(0xffff);
  disp_centered_text("Adding Credit Card To The Slot N" + String(chsn_slot) + "...", 5);
  disp_centered_text("Please wait for a while.", 17);
  clear_variables();
  encrypt_with_TDES_AES_Blowfish_Serp(entered_title);
  delay(DELAY_FOR_SLOTS);
  write_to_file_with_overwrite("/C" + String(chsn_slot) + "_ttl", dec_st);
  clear_variables();
  encrypt_with_TDES_AES_Blowfish_Serp(entered_cardholder);
  delay(DELAY_FOR_SLOTS);
  write_to_file_with_overwrite("/C" + String(chsn_slot) + "_hld", dec_st);
  clear_variables();
  encrypt_with_TDES_AES_Blowfish_Serp(entered_card_number);
  delay(DELAY_FOR_SLOTS);
  write_to_file_with_overwrite("/C" + String(chsn_slot) + "_nmr", dec_st);
  clear_variables();
  encrypt_with_TDES_AES_Blowfish_Serp(entered_expiry);
  delay(DELAY_FOR_SLOTS);
  write_to_file_with_overwrite("/C" + String(chsn_slot) + "_exp", dec_st);
  clear_variables();
  encrypt_with_TDES_AES_Blowfish_Serp(entered_cvn);
  delay(DELAY_FOR_SLOTS);
  write_to_file_with_overwrite("/C" + String(chsn_slot) + "_cvn", dec_st);
  clear_variables();
  encrypt_with_TDES_AES_Blowfish_Serp(entered_pin);
  delay(DELAY_FOR_SLOTS);
  write_to_file_with_overwrite("/C" + String(chsn_slot) + "_pin", dec_st);
  clear_variables();
  encrypt_with_TDES_AES_Blowfish_Serp(entered_zip_code);
  delay(DELAY_FOR_SLOTS);
  write_to_file_with_overwrite("/C" + String(chsn_slot) + "_zip", dec_st);
  clear_variables();
  encrypt_hash_with_tdes_aes_blf_srp(entered_title + entered_cardholder + entered_card_number + entered_expiry + entered_cvn + entered_pin + entered_zip_code);
  delay(DELAY_FOR_SLOTS);
  write_to_file_with_overwrite("/C" + String(chsn_slot) + "_tag", dec_st);
  return;
}

void update_credit_card_and_tag(int chsn_slot, String new_pin) {
  tft.fillScreen(0x0000);
  tft.setTextSize(1);
  tft.setTextColor(0xffff);
  tft.setCursor(0, 0);
  tft.print("Editing Credit Card In The Slot N" + String(chsn_slot) + "...");
  tft.setCursor(0, 10);
  tft.print("Please wait for a while.");
  clear_variables();
  encrypt_with_TDES_AES_Blowfish_Serp(new_pin);
  delay(DELAY_FOR_SLOTS);
  write_to_file_with_overwrite("/C" + String(chsn_slot) + "_pin", dec_st);
  clear_variables();
  decrypt_with_TDES_AES_Blowfish_Serp(read_file("/C" + String(chsn_slot) + "_ttl"));
  String decrypted_title = dec_st;
  clear_variables();
  decrypt_with_TDES_AES_Blowfish_Serp(read_file("/C" + String(chsn_slot) + "_hld"));
  String decrypted_cardholder = dec_st;
  clear_variables();
  decrypt_with_TDES_AES_Blowfish_Serp(read_file("/C" + String(chsn_slot) + "_nmr"));
  String decrypted_card_number = dec_st;
  clear_variables();
  decrypt_with_TDES_AES_Blowfish_Serp(read_file("/C" + String(chsn_slot) + "_exp"));
  String decrypted_expiry = dec_st;
  clear_variables();
  decrypt_with_TDES_AES_Blowfish_Serp(read_file("/C" + String(chsn_slot) + "_cvn"));
  String decrypted_cvn = dec_st;
  clear_variables();
  decrypt_with_TDES_AES_Blowfish_Serp(read_file("/C" + String(chsn_slot) + "_zip"));
  String decrypted_zip_code = dec_st;
  clear_variables();
  encrypt_hash_with_tdes_aes_blf_srp(decrypted_title + decrypted_cardholder + decrypted_card_number + decrypted_expiry + decrypted_cvn + new_pin + decrypted_zip_code);
  delay(DELAY_FOR_SLOTS);
  write_to_file_with_overwrite("/C" + String(chsn_slot) + "_tag", dec_st);
  return;
}

void edit_credit_card_from_nint_controller(int chsn_slot) {
  if (read_file("/C" + String(chsn_slot) + "_pin") == "-1") {
    tft.fillScreen(0x0000);
    tft.setTextColor(0x07e0);
    tft.setTextSize(2);
    disp_centered_text("The Slot N" + String(chsn_slot) + " is Empty", 5);
    tft.setTextColor(0xffff);
    tft.setTextSize(1);
    disp_centered_text("Press any key to return to the main menu", 232);
    press_any_key_to_continue();
  } else {
    clear_variables();
    decrypt_with_TDES_AES_Blowfish_Serp(read_file("/C" + String(chsn_slot) + "_pin"));
    String old_pin = dec_st;
    act = true;
    clear_variables();
    set_stuff_for_input("Edit PIN");
    keyboard_input = old_pin;
    disp();
    keyb_input();
    if (act == true) {
      update_credit_card_and_tag(chsn_slot, keyboard_input);
    }
  }
  return;
}

void delete_credit_card(int chsn_slot) {
  tft.fillScreen(0x0000);
  tft.setTextSize(1);
  tft.setTextColor(0xffff);
  tft.setCursor(0, 0);
  tft.print("Deleting Credit Card From The Slot N" + String(chsn_slot) + "...");
  tft.setCursor(0, 10);
  tft.print("Please wait for a while.");
  delete_file("/C" + String(chsn_slot) + "_tag");
  delete_file("/C" + String(chsn_slot) + "_ttl");
  delete_file("/C" + String(chsn_slot) + "_hld");
  delete_file("/C" + String(chsn_slot) + "_nmr");
  delete_file("/C" + String(chsn_slot) + "_exp");
  delete_file("/C" + String(chsn_slot) + "_cvn");
  delete_file("/C" + String(chsn_slot) + "_pin");
  delete_file("/C" + String(chsn_slot) + "_zip");
  clear_variables();
  call_main_menu();
  return;
}

void view_credit_card(int chsn_slot) {
  if (read_file("/C" + String(chsn_slot) + "_ttl") == "-1") {
    tft.fillScreen(0x0000);
    tft.setTextColor(0x07e0);
    tft.setTextSize(2);
    disp_centered_text("The Slot N" + String(chsn_slot) + " is Empty", 5);
    tft.setTextColor(0xffff);
    tft.setTextSize(1);
    disp_centered_text("Press any key to return to the main menu", 232);
    press_any_key_to_continue();
  } else {
    clear_variables();
    decrypt_with_TDES_AES_Blowfish_Serp(read_file("/C" + String(chsn_slot) + "_ttl"));
    String decrypted_title = dec_st;
    clear_variables();
    decrypt_with_TDES_AES_Blowfish_Serp(read_file("/C" + String(chsn_slot) + "_hld"));
    String decrypted_cardholder = dec_st;
    clear_variables();
    decrypt_with_TDES_AES_Blowfish_Serp(read_file("/C" + String(chsn_slot) + "_nmr"));
    String decrypted_card_number = dec_st;
    clear_variables();
    decrypt_with_TDES_AES_Blowfish_Serp(read_file("/C" + String(chsn_slot) + "_exp"));
    String decrypted_expiry = dec_st;
    clear_variables();
    decrypt_with_TDES_AES_Blowfish_Serp(read_file("/C" + String(chsn_slot) + "_cvn"));
    String decrypted_cvn = dec_st;
    clear_variables();
    decrypt_with_TDES_AES_Blowfish_Serp(read_file("/C" + String(chsn_slot) + "_pin"));
    String decrypted_pin = dec_st;
    clear_variables();
    decrypt_with_TDES_AES_Blowfish_Serp(read_file("/C" + String(chsn_slot) + "_zip"));
    String decrypted_zip_code = dec_st;
    decrypt_tag_with_TDES_AES_Blowfish_Serp(read_file("/C" + String(chsn_slot) + "_tag"));
    dec_st = decrypted_title + decrypted_cardholder + decrypted_card_number + decrypted_expiry + decrypted_cvn + decrypted_pin + decrypted_zip_code;
    bool credit_card_integrity = verify_integrity();

    if (credit_card_integrity == true) {
      tft.fillScreen(0x0000);
      tft.setTextSize(2);
      tft.setCursor(0, 5);
      tft.setTextColor(current_inact_clr);
      tft.print("Title:");
      tft.setTextColor(0xffff);
      tft.println(decrypted_title);
      tft.setTextColor(current_inact_clr);
      tft.print("Cardholder Name:");
      tft.setTextColor(0xffff);
      tft.println(decrypted_cardholder);
      tft.setTextColor(current_inact_clr);
      tft.print("Card Number:");
      tft.setTextColor(0xffff);
      tft.println(decrypted_card_number);
      tft.setTextColor(current_inact_clr);
      tft.print("Expiration Date:");
      tft.setTextColor(0xffff);
      tft.println(decrypted_expiry);
      tft.setTextColor(current_inact_clr);
      tft.print("CVN:");
      tft.setTextColor(0xffff);
      tft.println(decrypted_cvn);
      tft.setTextColor(current_inact_clr);
      tft.print("PIN:");
      tft.setTextColor(0xffff);
      tft.println(decrypted_pin);
      tft.setTextColor(current_inact_clr);
      tft.print("ZIP Code:");
      tft.setTextColor(0xffff);
      tft.println(decrypted_zip_code);
      tft.setTextSize(1);
      tft.fillRect(0, 230, 320, 14, 0x0000);
      tft.fillRect(312, 0, 8, 240, current_inact_clr);
      disp_centered_text("Integrity Verified Successfully!", 232);
    } else {
      tft.fillScreen(0x0000);
      tft.setTextSize(2);
      tft.setCursor(0, 5);
      tft.setTextColor(current_inact_clr);
      tft.print("Title:");
      tft.setTextColor(five_six_five_red_color);
      tft.println(decrypted_title);
      tft.setTextColor(current_inact_clr);
      tft.print("Cardholder Name:");
      tft.setTextColor(five_six_five_red_color);
      tft.println(decrypted_cardholder);
      tft.setTextColor(current_inact_clr);
      tft.print("Card Number:");
      tft.setTextColor(five_six_five_red_color);
      tft.println(decrypted_card_number);
      tft.setTextColor(current_inact_clr);
      tft.print("Expiration Date:");
      tft.setTextColor(five_six_five_red_color);
      tft.println(decrypted_expiry);
      tft.setTextColor(current_inact_clr);
      tft.print("CVN:");
      tft.setTextColor(five_six_five_red_color);
      tft.println(decrypted_cvn);
      tft.setTextColor(current_inact_clr);
      tft.print("PIN:");
      tft.setTextColor(five_six_five_red_color);
      tft.println(decrypted_pin);
      tft.setTextColor(current_inact_clr);
      tft.print("ZIP Code:");
      tft.setTextColor(five_six_five_red_color);
      tft.println(decrypted_zip_code);
      tft.setTextSize(1);
      tft.fillRect(0, 230, 320, 14, 0x0000);
      tft.fillRect(312, 0, 8, 240, five_six_five_red_color);
      disp_centered_text("Integrity Verification Failed!", 232);
    }
    act = false;
    tab_to_print_rec_to_serial_terminal();
    if (act == true) {
      Serial.println();
      Serial.print("Title:\"");
      Serial.print(decrypted_title);
      Serial.println("\"");
      Serial.print("Cardholder Name:\"");
      Serial.print(decrypted_cardholder);
      Serial.println("\"");
      Serial.print("Card Number:\"");
      Serial.print(decrypted_card_number);
      Serial.println("\"");
      Serial.print("Expiration Date:\"");
      Serial.print(decrypted_expiry);
      Serial.println("\"");
      Serial.print("CVN:\"");
      Serial.print(decrypted_cvn);
      Serial.println("\"");
      Serial.print("PIN:\"");
      Serial.print(decrypted_pin);
      Serial.println("\"");
      Serial.print("ZIP Code:\"");
      Serial.print(decrypted_zip_code);
      Serial.println("\"");
      if (credit_card_integrity == true) {
        Serial.println("Integrity Verified Successfully!\n");
      } else {
        Serial.println("Integrity Verification Failed!!!\n");
      }
    }
  }
}

// Functions for Credit Cards (Above)

// Functions for Notes (Below)

void select_note(byte what_to_do_with_it) {
  // 0 - Add note
  // 1 - Edit note
  // 2 - Delete note
  // 3 - View note
  delay(DELAY_FOR_SLOTS);
  curr_key = 1;

  header_for_select_note(what_to_do_with_it);
  display_title_from_note_without_integrity_verification();
  bool continue_to_next = false;
  while (continue_to_next == false) {
    byte input_data = get_PS2_keyb_input();
    if (input_data > 0) {

      if (input_data == 130)
        curr_key++;

      if (input_data == 129)
        curr_key--;

      if (curr_key < 1)
        curr_key = MAX_NUM_OF_RECS;

      if (curr_key > MAX_NUM_OF_RECS)
        curr_key = 1;

      if (input_data == 13 || input_data == 133) { // Enter
        int chsn_slot = curr_key;
        if (what_to_do_with_it == 0 && continue_to_next == false) {
          continue_to_next = true;
          add_note_from_nint_controller(chsn_slot);
        }
        if (what_to_do_with_it == 1 && continue_to_next == false) {
          continue_to_next = true;
          tft.fillScreen(0x0000);
          tft.setTextSize(1);
          tft.setTextColor(0xffff);
          tft.setCursor(0, 0);
          tft.print("Decrypting the record...");
          tft.setCursor(0, 10);
          tft.print("Please wait for a while.");
          edit_note_from_nint_controller(chsn_slot);
        }
        if (what_to_do_with_it == 2 && continue_to_next == false) {
          continue_to_next = true;
          delete_note(chsn_slot);
        }
        if (what_to_do_with_it == 3 && continue_to_next == false) {
          continue_to_next = true;
          tft.fillScreen(0x0000);
          tft.setTextSize(1);
          tft.setTextColor(0xffff);
          tft.setCursor(0, 0);
          tft.print("Decrypting the record...");
          tft.setCursor(0, 10);
          tft.print("Please wait for a while.");
          view_note(chsn_slot);
        }
        continue_to_next = true;
        break;
      }

      if (input_data == 8 || input_data == 27) {
        call_main_menu();
        continue_to_next = true;
        break;
      }
      delay(DELAY_FOR_SLOTS);
      header_for_select_note(what_to_do_with_it);
      display_title_from_note_without_integrity_verification();
    }
    delayMicroseconds(500);
  }
  return;
}

void header_for_select_note(byte what_to_do_with_it) {
  tft.fillScreen(0x0000);
  tft.setTextSize(2);
  if (what_to_do_with_it == 0) {
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Add Note to Slot " + String(curr_key) + "/" + String(MAX_NUM_OF_RECS), 5);
    disp_button_designation();
  }
  if (what_to_do_with_it == 1) {
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Edit Note " + String(curr_key) + "/" + String(MAX_NUM_OF_RECS), 5);
    disp_button_designation();
  }
  if (what_to_do_with_it == 2) {
    tft.setTextColor(five_six_five_red_color);
    disp_centered_text("Delete Note " + String(curr_key) + "/" + String(MAX_NUM_OF_RECS), 5);
    disp_button_designation_for_del();
  }
  if (what_to_do_with_it == 3) {
    tft.setTextColor(current_inact_clr);
    disp_centered_text("View Note " + String(curr_key) + "/" + String(MAX_NUM_OF_RECS), 5);
    disp_button_designation();
  }
}

void display_title_from_note_without_integrity_verification() {
  tft.setTextSize(2);
  String encrypted_title = read_file("/N" + String(curr_key) + "_ttl");
  if (encrypted_title == "-1") {
    tft.setTextColor(0x07e0);
    disp_centered_text("Empty", 35);
  } else {
    clear_variables();
    decrypt_tag = false;
    decrypt_with_TDES_AES_Blowfish_Serp(encrypted_title);
    tft.setTextColor(0xffff);
    disp_centered_text(dec_st, 35);
  }
}

void add_note_from_nint_controller(int chsn_slot) {
  enter_title_for_note(chsn_slot);
  clear_variables();
  call_main_menu();
  return;
}

void enter_title_for_note(int chsn_slot) {
  act = true;
  clear_variables();
  set_stuff_for_input("Enter Title");
  keyb_input();
  if (act == true) {
    enter_content_for_note(chsn_slot, keyboard_input);
  }
  return;
}

void enter_content_for_note(int chsn_slot, String entered_title) {
  act = true;
  clear_variables();
  set_stuff_for_input("Enter Content");
  keyb_input();
  if (act == true) {
    write_note_to_flash(chsn_slot, entered_title, keyboard_input);
  }
  return;
}

void write_note_to_flash(int chsn_slot, String entered_title, String entered_content) {
  tft.fillScreen(0x0000);
  tft.setTextSize(1);
  tft.setTextColor(0xffff);
  disp_centered_text("Adding Note To The Slot N" + String(chsn_slot) + "...", 5);
  disp_centered_text("Please wait for a while.", 17);
  clear_variables();
  encrypt_with_TDES_AES_Blowfish_Serp(entered_title);
  delay(DELAY_FOR_SLOTS);
  write_to_file_with_overwrite("/N" + String(chsn_slot) + "_ttl", dec_st);
  clear_variables();
  encrypt_with_TDES_AES_Blowfish_Serp(entered_content);
  delay(DELAY_FOR_SLOTS);
  write_to_file_with_overwrite("/N" + String(chsn_slot) + "_cnt", dec_st);
  clear_variables();
  encrypt_hash_with_tdes_aes_blf_srp(entered_title + entered_content);
  delay(DELAY_FOR_SLOTS);
  write_to_file_with_overwrite("/N" + String(chsn_slot) + "_tag", dec_st);
  return;
}

void update_note_and_tag(int chsn_slot, String new_content) {
  tft.fillScreen(0x0000);
  tft.setTextSize(1);
  tft.setTextColor(0xffff);
  tft.setCursor(0, 0);
  tft.print("Editing Note In The Slot N" + String(chsn_slot) + "...");
  tft.setCursor(0, 10);
  tft.print("Please wait for a while.");

  clear_variables();
  encrypt_with_TDES_AES_Blowfish_Serp(new_content);
  write_to_file_with_overwrite("/N" + String(chsn_slot) + "_cnt", dec_st);

  clear_variables();
  decrypt_with_TDES_AES_Blowfish_Serp(read_file("/N" + String(chsn_slot) + "_ttl"));
  String decrypted_title = dec_st;

  clear_variables();
  encrypt_hash_with_tdes_aes_blf_srp(decrypted_title + new_content);
  delay(DELAY_FOR_SLOTS);
  write_to_file_with_overwrite("/N" + String(chsn_slot) + "_tag", dec_st);
  return;
}

void edit_note_from_nint_controller(int chsn_slot) {
  if (read_file("/N" + String(chsn_slot) + "_cnt") == "-1") {
    tft.fillScreen(0x0000);
    tft.setTextColor(0x07e0);
    tft.setTextSize(2);
    disp_centered_text("The Slot N" + String(chsn_slot) + " is Empty", 5);
    tft.setTextColor(0xffff);
    tft.setTextSize(1);
    disp_centered_text("Press any key to return to the main menu", 232);
    press_any_key_to_continue();
  } else {
    clear_variables();
    decrypt_with_TDES_AES_Blowfish_Serp(read_file("/N" + String(chsn_slot) + "_cnt"));
    String old_password = dec_st;
    act = true;
    clear_variables();
    set_stuff_for_input("Edit Note");
    keyboard_input = old_password;
    disp();
    keyb_input();
    if (act == true) {
      update_note_and_tag(chsn_slot, keyboard_input);
    }
  }
  return;
}

void delete_note(int chsn_slot) {
  tft.fillScreen(0x0000);
  tft.setTextSize(1);
  tft.setTextColor(0xffff);
  tft.setCursor(0, 0);
  tft.print("Deleting Note From The Slot N" + String(chsn_slot) + "...");
  tft.setCursor(0, 10);
  tft.print("Please wait for a while.");
  delete_file("/N" + String(chsn_slot) + "_tag");
  delete_file("/N" + String(chsn_slot) + "_ttl");
  delete_file("/N" + String(chsn_slot) + "_cnt");
  clear_variables();
  call_main_menu();
  return;
}

void view_note(int chsn_slot) {
  if (read_file("/N" + String(chsn_slot) + "_ttl") == "-1") {
    tft.fillScreen(0x0000);
    tft.setTextColor(0x07e0);
    tft.setTextSize(2);
    disp_centered_text("The Slot N" + String(chsn_slot) + " is Empty", 5);
    tft.setTextColor(0xffff);
    tft.setTextSize(1);
    disp_centered_text("Press any key to return to the main menu", 232);
    press_any_key_to_continue();
  } else {
    clear_variables();
    decrypt_with_TDES_AES_Blowfish_Serp(read_file("/N" + String(chsn_slot) + "_ttl"));
    String decrypted_title = dec_st;
    clear_variables();
    decrypt_with_TDES_AES_Blowfish_Serp(read_file("/N" + String(chsn_slot) + "_cnt"));
    String decrypted_content = dec_st;
    clear_variables();
    decrypt_tag_with_TDES_AES_Blowfish_Serp(read_file("/N" + String(chsn_slot) + "_tag"));
    dec_st = decrypted_title + decrypted_content;
    bool login_integrity = verify_integrity();

    if (login_integrity == true) {
      tft.fillScreen(0x0000);
      tft.setTextSize(2);
      tft.setCursor(0, 5);
      tft.setTextColor(current_inact_clr);
      tft.print("Title:");
      tft.setTextColor(0xffff);
      tft.println(decrypted_title);
      tft.setTextColor(current_inact_clr);
      tft.print("Content:");
      tft.setTextColor(0xffff);
      tft.println(decrypted_content);
      tft.setTextSize(1);
      tft.fillRect(0, 230, 320, 14, 0x0000);
      tft.fillRect(312, 0, 8, 240, current_inact_clr);
      disp_centered_text("Integrity Verified Successfully!", 232);
    } else {
      tft.fillScreen(0x0000);
      tft.setTextSize(2);
      tft.setCursor(0, 5);
      tft.setTextColor(current_inact_clr);
      tft.print("Title:");
      tft.setTextColor(five_six_five_red_color);
      tft.println(decrypted_title);
      tft.setTextColor(current_inact_clr);
      tft.print("Content:");
      tft.setTextColor(five_six_five_red_color);
      tft.println(decrypted_content);
      tft.setTextSize(1);
      tft.fillRect(0, 230, 320, 14, 0x0000);
      tft.fillRect(312, 0, 8, 240, five_six_five_red_color);
      disp_centered_text("Integrity Verification Failed!", 232);
    }
    act = false;
    tab_to_print_rec_to_serial_terminal();
    if (act == true) {
      Serial.println();
      Serial.print("Title:\"");
      Serial.print(decrypted_title);
      Serial.println("\"");
      Serial.print("Content:\"");
      Serial.print(decrypted_content);
      Serial.println("\"");
      if (login_integrity == true) {
        Serial.println("Integrity Verified Successfully!\n");
      } else {
        Serial.println("Integrity Verification Failed!!!\n");
      }
    }
  }
}

// Functions for Notes (Above)

// Functions for Phone Numbers (Below)

void select_phone_number(byte what_to_do_with_it) {
  // 0 - Add phone_number
  // 1 - Edit phone_number
  // 2 - Delete phone_number
  // 3 - View phone_number
  delay(DELAY_FOR_SLOTS);
  curr_key = 1;

  header_for_select_phone_number(what_to_do_with_it);
  display_title_from_phone_number_without_integrity_verification();
  bool continue_to_next = false;
  while (continue_to_next == false) {
    byte input_data = get_PS2_keyb_input();
    if (input_data > 0) {

      if (input_data == 130)
        curr_key++;

      if (input_data == 129)
        curr_key--;

      if (curr_key < 1)
        curr_key = MAX_NUM_OF_RECS;

      if (curr_key > MAX_NUM_OF_RECS)
        curr_key = 1;

      if (input_data == 13 || input_data == 133) { // Enter
        int chsn_slot = curr_key;
        if (what_to_do_with_it == 0 && continue_to_next == false) {
          continue_to_next = true;
          add_phone_number_from_nint_controller(chsn_slot);
        }
        if (what_to_do_with_it == 1 && continue_to_next == false) {
          continue_to_next = true;
          tft.fillScreen(0x0000);
          tft.setTextSize(1);
          tft.setTextColor(0xffff);
          tft.setCursor(0, 0);
          tft.print("Decrypting the record...");
          tft.setCursor(0, 10);
          tft.print("Please wait for a while.");
          edit_phone_number_from_nint_controller(chsn_slot);
        }
        if (what_to_do_with_it == 2 && continue_to_next == false) {
          continue_to_next = true;
          delete_phone_number(chsn_slot);
        }
        if (what_to_do_with_it == 3 && continue_to_next == false) {
          continue_to_next = true;
          tft.fillScreen(0x0000);
          tft.setTextSize(1);
          tft.setTextColor(0xffff);
          tft.setCursor(0, 0);
          tft.print("Decrypting the record...");
          tft.setCursor(0, 10);
          tft.print("Please wait for a while.");
          view_phone_number(chsn_slot);
        }
        continue_to_next = true;
        break;
      }

      if (input_data == 8 || input_data == 27) {
        call_main_menu();
        continue_to_next = true;
        break;
      }
      delay(DELAY_FOR_SLOTS);
      header_for_select_phone_number(what_to_do_with_it);
      display_title_from_phone_number_without_integrity_verification();
    }
    delayMicroseconds(500);
  }
  return;
}

void header_for_select_phone_number(byte what_to_do_with_it) {
  tft.fillScreen(0x0000);
  tft.setTextSize(2);
  if (what_to_do_with_it == 0) {
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Add Phone to Slot " + String(curr_key) + "/" + String(MAX_NUM_OF_RECS), 5);
    disp_button_designation();
  }
  if (what_to_do_with_it == 1) {
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Edit Phone Number " + String(curr_key) + "/" + String(MAX_NUM_OF_RECS), 5);
    disp_button_designation();
  }
  if (what_to_do_with_it == 2) {
    tft.setTextColor(five_six_five_red_color);
    disp_centered_text("Delete Phone " + String(curr_key) + "/" + String(MAX_NUM_OF_RECS), 5);
    disp_button_designation_for_del();
  }
  if (what_to_do_with_it == 3) {
    tft.setTextColor(current_inact_clr);
    disp_centered_text("View Phone Number " + String(curr_key) + "/" + String(MAX_NUM_OF_RECS), 5);
    disp_button_designation();
  }
}

void display_title_from_phone_number_without_integrity_verification() {
  tft.setTextSize(2);
  String encrypted_title = read_file("/P" + String(curr_key) + "_ttl");
  if (encrypted_title == "-1") {
    tft.setTextColor(0x07e0);
    disp_centered_text("Empty", 35);
  } else {
    clear_variables();
    decrypt_tag = false;
    decrypt_with_TDES_AES_Blowfish_Serp(encrypted_title);
    tft.setTextColor(0xffff);
    disp_centered_text(dec_st, 35);
  }
}

void add_phone_number_from_nint_controller(int chsn_slot) {
  enter_title_for_phone_number(chsn_slot);
  clear_variables();
  call_main_menu();
  return;
}

void enter_title_for_phone_number(int chsn_slot) {
  act = true;
  clear_variables();
  set_stuff_for_input("Enter Title");
  keyb_input();
  if (act == true) {
    enter_phone_number_for_phone_number(chsn_slot, keyboard_input);
  }
  return;
}

void enter_phone_number_for_phone_number(int chsn_slot, String entered_title) {
  act = true;
  clear_variables();
  set_stuff_for_input("Enter Phone Number");
  keyb_input();
  if (act == true) {
    write_phone_number_to_flash(chsn_slot, entered_title, keyboard_input);
  }
  return;
}

void write_phone_number_to_flash(int chsn_slot, String entered_title, String entered_phone_number) {
  tft.fillScreen(0x0000);
  tft.setTextSize(1);
  tft.setTextColor(0xffff);
  disp_centered_text("Adding Phone Number To The Slot N" + String(chsn_slot) + "...", 5);
  disp_centered_text("Please wait for a while.", 17);
  clear_variables();
  encrypt_with_TDES_AES_Blowfish_Serp(entered_title);
  delay(DELAY_FOR_SLOTS);
  write_to_file_with_overwrite("/P" + String(chsn_slot) + "_ttl", dec_st);
  clear_variables();
  encrypt_with_TDES_AES_Blowfish_Serp(entered_phone_number);
  delay(DELAY_FOR_SLOTS);
  write_to_file_with_overwrite("/P" + String(chsn_slot) + "_cnt", dec_st);
  clear_variables();
  encrypt_hash_with_tdes_aes_blf_srp(entered_title + entered_phone_number);
  delay(DELAY_FOR_SLOTS);
  write_to_file_with_overwrite("/P" + String(chsn_slot) + "_tag", dec_st);
  return;
}

void update_phone_number_and_tag(int chsn_slot, String new_phone_number) {
  tft.fillScreen(0x0000);
  tft.setTextSize(1);
  tft.setTextColor(0xffff);
  tft.setCursor(0, 0);
  tft.print("Editing Phone Number In The Slot N" + String(chsn_slot) + "...");
  tft.setCursor(0, 10);
  tft.print("Please wait for a while.");

  clear_variables();
  encrypt_with_TDES_AES_Blowfish_Serp(new_phone_number);
  delay(DELAY_FOR_SLOTS);
  write_to_file_with_overwrite("/P" + String(chsn_slot) + "_cnt", dec_st);

  clear_variables();
  decrypt_with_TDES_AES_Blowfish_Serp(read_file("/P" + String(chsn_slot) + "_ttl"));
  String decrypted_title = dec_st;

  clear_variables();
  encrypt_hash_with_tdes_aes_blf_srp(decrypted_title + new_phone_number);
  delay(DELAY_FOR_SLOTS);
  write_to_file_with_overwrite("/P" + String(chsn_slot) + "_tag", dec_st);
  return;
}

void edit_phone_number_from_nint_controller(int chsn_slot) {
  if (read_file("/P" + String(chsn_slot) + "_cnt") == "-1") {
    tft.fillScreen(0x0000);
    tft.setTextColor(0x07e0);
    tft.setTextSize(2);
    disp_centered_text("The Slot N" + String(chsn_slot) + " is Empty", 5);
    tft.setTextColor(0xffff);
    tft.setTextSize(1);
    disp_centered_text("Press any key to return to the main menu", 232);
    press_any_key_to_continue();
  } else {
    clear_variables();
    decrypt_with_TDES_AES_Blowfish_Serp(read_file("/P" + String(chsn_slot) + "_cnt"));
    String old_password = dec_st;
    act = true;
    clear_variables();
    set_stuff_for_input("Edit Phone Number");
    keyboard_input = old_password;
    disp();
    keyb_input();
    if (act == true) {
      update_phone_number_and_tag(chsn_slot, keyboard_input);
    }
  }
  return;
}

void delete_phone_number(int chsn_slot) {
  tft.fillScreen(0x0000);
  tft.setTextSize(1);
  tft.setTextColor(0xffff);
  tft.setCursor(0, 0);
  tft.print("Deleting Phone Number From The Slot N" + String(chsn_slot) + "...");
  tft.setCursor(0, 10);
  tft.print("Please wait for a while.");
  delete_file("/P" + String(chsn_slot) + "_tag");
  delete_file("/P" + String(chsn_slot) + "_ttl");
  delete_file("/P" + String(chsn_slot) + "_cnt");
  clear_variables();
  call_main_menu();
  return;
}

void view_phone_number(int chsn_slot) {
  if (read_file("/P" + String(chsn_slot) + "_ttl") == "-1") {
    tft.fillScreen(0x0000);
    tft.setTextColor(0x07e0);
    tft.setTextSize(2);
    disp_centered_text("The Slot N" + String(chsn_slot) + " is Empty", 5);
    tft.setTextColor(0xffff);
    tft.setTextSize(1);
    disp_centered_text("Press any key to return to the main menu", 232);
    press_any_key_to_continue();
  } else {
    clear_variables();
    decrypt_with_TDES_AES_Blowfish_Serp(read_file("/P" + String(chsn_slot) + "_ttl"));
    String decrypted_title = dec_st;
    clear_variables();
    decrypt_with_TDES_AES_Blowfish_Serp(read_file("/P" + String(chsn_slot) + "_cnt"));
    String decrypted_phone_number = dec_st;
    clear_variables();
    decrypt_tag_with_TDES_AES_Blowfish_Serp(read_file("/P" + String(chsn_slot) + "_tag"));
    dec_st = decrypted_title + decrypted_phone_number;
    bool login_integrity = verify_integrity();

    if (login_integrity == true) {
      tft.fillScreen(0x0000);
      tft.setTextSize(2);
      tft.setCursor(0, 5);
      tft.setTextColor(current_inact_clr);
      tft.print("Title:");
      tft.setTextColor(0xffff);
      tft.println(decrypted_title);
      tft.setTextColor(current_inact_clr);
      tft.print("Phone Number:");
      tft.setTextColor(0xffff);
      tft.println(decrypted_phone_number);
      tft.setTextSize(1);
      tft.fillRect(0, 230, 320, 14, 0x0000);
      tft.fillRect(312, 0, 8, 240, current_inact_clr);
      disp_centered_text("Integrity Verified Successfully!", 232);
    } else {
      tft.fillScreen(0x0000);
      tft.setTextSize(2);
      tft.setCursor(0, 5);
      tft.setTextColor(current_inact_clr);
      tft.print("Title:");
      tft.setTextColor(five_six_five_red_color);
      tft.println(decrypted_title);
      tft.setTextColor(current_inact_clr);
      tft.print("Phone Number:");
      tft.setTextColor(five_six_five_red_color);
      tft.println(decrypted_phone_number);
      tft.setTextSize(1);
      tft.fillRect(0, 230, 320, 14, 0x0000);
      tft.fillRect(312, 0, 8, 240, five_six_five_red_color);
      disp_centered_text("Integrity Verification Failed!", 232);
    }
    act = false;
    tab_to_print_rec_to_serial_terminal();
    if (act == true) {
      Serial.println();
      Serial.print("Title:\"");
      Serial.print(decrypted_title);
      Serial.println("\"");
      Serial.print("Phone Number:\"");
      Serial.print(decrypted_phone_number);
      Serial.println("\"");
      if (login_integrity == true) {
        Serial.println("Integrity Verified Successfully!\n");
      } else {
        Serial.println("Integrity Verification Failed!!!\n");
      }
    }
  }
}

// Functions for Phone Number (Above)

void press_key_on_keyboard() {
  bool break_loop = false;
  while (break_loop == false) {
    code = keyboard.available();
    if (code > 0) {
      code = keyboard.read();
      code = keymap.remapKey(code);
      if (code > 0) {
        if ((code & 0xFF)) {

          if ((code & 0xFF) == 27) { // Esc
            cont_t_nxt = false;
            break_loop = true;
          } else if ((code & 0xFF) == 13) { // Enter
            cont_t_nxt = true;
            break_loop = true;
          }
        }

      }
    }

    delayMicroseconds(400);
  }
}

void enter_operator_password_to_continue(byte cps) {
  clear_variables();
  set_stuff_for_input("Enter Operator Password");
  star_keyb_input();
  String read_keyboard_input = keyboard_input;
  if (finish_input == true) {
    clear_variables();
    SHA256HMAC hmac(hmackey, sizeof(hmackey));
    int str_len = read_keyboard_input.length() + 1;
    char read_keyboard_input_arr[str_len];
    read_keyboard_input.toCharArray(read_keyboard_input_arr, str_len);
    hmac.doUpdate(read_keyboard_input_arr);
    byte authCode[SHA256HMAC_SIZE];
    hmac.doFinal(authCode);
    String hashed_operator_password;
    for (int i = 0; i < 30; i++) {
      if (authCode[i] < 16)
        hashed_operator_password += "0";
      hashed_operator_password += String(authCode[i], HEX);
    }
    back_keys();
    clear_variables();
    //Serial.println(read_file("/oprpsswd"));
    decrypt_tag_with_TDES_AES_Blowfish_Serp(read_file("/oprpsswd"));
    //Serial.println(dec_tag);
    //Serial.println(hashed_operator_password);
    for (int i = 10; i < 28; i++) {
      serp_key[i] = authCode[i];
    }
    if (dec_tag.equals(hashed_operator_password) && cps > 1) {
      if (cps < 4) {
        tft.fillScreen(0x0000);
        tft.setTextSize(2);
        tft.setTextColor(0xffff);
        disp_centered_text("Press '#'", 45);
        disp_centered_text("And Give The Device", 65);
        disp_centered_text("To The Client", 85);
        disp_centered_text("Press 'C' to Cancel", 220);
        cont_t_nxt = false;
        press_key_on_keyboard();
      } else {
        cont_t_nxt = true;
      }
      if (cont_t_nxt == true) {
        if (cps == 2)
          create_new_account();
        if (cps == 3)
          view_account_balance();
        if (cps == 4)
          action_for_oth_opt();
      }
    } else if (dec_tag.equals(hashed_operator_password) && cps < 2) {
      if (cps == 0)
        reduce_account_balance();
      if (cps == 1)
        add_money_to_account();
    } else {
      tft.fillScreen(0x0000);
      tft.setTextSize(2);
      tft.setTextColor(five_six_five_red_color);
      disp_centered_text("Wrong Operator Password!", 45);
      tft.setTextColor(0xffff);
      disp_centered_text("Please reboot", 80);
      disp_centered_text("the device", 100);
      disp_centered_text("and try again", 120);
      for (;;)
        delay(1000);
    }
  } else {

  }
  call_main_menu();
}

void create_new_account() {
  tft.setTextSize(2);
  tft.fillScreen(0x155b);
  tft.setTextColor(0xffff);
  disp_centered_text("Approximate the card to", 90);
  disp_centered_text("the RFID reader", 110);
  disp_centered_text("Press 'C' to Cancel", 220);
  cont_to_next_step = true;
  get_input_from_arduino_uno_key_to_canc();
  for (int i = 0; i < 4; i++){
    read_cards[i] = read_card_rec_from_arduino[i];
  }
  if (cont_to_next_step == true) {
    for (int i = 0; i < 4; i++) {
      serp_key[i + 28] = read_cards[i];
    }
    tft.fillScreen(0x155b);
    disp_centered_text("Set your PIN", 60);
    disp_centered_text("Remember that it can't", 80);
    disp_centered_text("be changed!!!", 100);
    disp_centered_text("* - Backspace", 180);
    disp_centered_text("# - Enter", 200);
    disp_centered_text("C - Cancel", 220);
    tft.fillRect(102, 135, 116, 32, 0x08c5);
    tft.setCursor(112, 145);
    tft.setTextColor(0xffff, 0x08c5);
    cont_t_nxt = false;
    bool setp1 = false;
    String pin1;
    String pin2;
    while (setp1 != true) {

      code = keyboard.available();
      if (code > 0) {
        code = keyboard.read();
        code = keymap.remapKey(code);
        if (code > 0) {
          if ((code & 0xFF)) {

            if ((code & 0xFF) == 27) { // Esc
              cont_t_nxt = false;
              setp1 = true;
            } else if ((code & 0xFF) == 13) { // Enter
              cont_t_nxt = true;
              setp1 = true;
            } else if ((code & 0xFF) == 8) { // Backspace
              pin1.remove(pin1.length() - 1, 1);
              tft.fillRect(102, 135, 116, 32, 0x08c5);
            } else {
              if (pin1.length() < 8)
                pin1 += char(code & 0xFF);
            }

            tft.setCursor(112, 140);
            tft.setTextColor(0xffff, 0x08c5);
            String stars;
            for (int i = 0; i < pin1.length(); i++) {
              stars += "*";
            }
            tft.println(stars);
          }

        }
      }

      delayMicroseconds(400);
    }
    if (cont_t_nxt == true) {
      tft.fillScreen(0x155b);
      tft.setTextColor(0xffff, 0x155b);
      disp_centered_text("Enter your PIN again", 80);
      disp_centered_text("* - Backspace", 190);
      disp_centered_text("# - Enter", 210);
      tft.fillRect(102, 135, 116, 32, 0x08c5);
      tft.setCursor(112, 140);
      tft.setTextColor(0xffff, 0x08c5);
      cont_t_nxt = false;
      bool setp2 = false;
      while (setp2 != true) {

        code = keyboard.available();
        if (code > 0) {
          code = keyboard.read();
          code = keymap.remapKey(code);
          if (code > 0) {
            if ((code & 0xFF)) {

              if ((code & 0xFF) == 27) { // Esc
                cont_t_nxt = false;
                setp2 = true;
              } else if ((code & 0xFF) == 13) { // Enter
                cont_t_nxt = true;
                setp2 = true;
              } else if ((code & 0xFF) == 8) { // Backspace
                pin2.remove(pin2.length() - 1, 1);
                tft.fillRect(102, 135, 116, 32, 0x08c5);
              } else {
                if (pin2.length() < 8)
                  pin2 += char(code & 0xFF);
              }

              tft.setCursor(112, 140);
              tft.setTextColor(0xffff, 0x08c5);
              String stars;
              for (int i = 0; i < pin2.length(); i++) {
                stars += "*";
              }
              tft.println(stars);
            }

          }
        }

        delayMicroseconds(400);
      }
    }

    //Serial.println(pin1);
    //Serial.println(pin2);
    if (cont_t_nxt == true) {
      if (pin1.equals(pin2) && pin1.length() > 0) {
        for (int i = 0; i < 4; i++) {
          serp_key[i + 28] = read_cards[i];
        }
        String read_card;
        for (int i = 0; i < 4; i++) {
          if (read_cards[i] < 16)
            read_card += "0";
          read_card += String(read_cards[i], HEX);
        }
        String read_crd_bck = read_card;
        read_card += pin2;
        //Serial.println(read_card);
        gen_r = false;
        back_keys();
        dec_st = "";
        encrypt_hash_with_tdes_aes_blf_srp(read_card);
        rest_keys();
        int dec_st_len = dec_st.length() + 1;
        char dec_st_array[dec_st_len];
        dec_st.toCharArray(dec_st_array, dec_st_len);
        //Serial.println(dec_st);
        byte res[25];
        for (int i = 0; i < 50; i += 2) {
          if (i == 0) {
            if (dec_st_array[i + 26] != 0 && dec_st_array[i + 26 + 1] != 0)
              res[i] = 16 * getNum(dec_st_array[i + 26]) + getNum(dec_st_array[i + 26 + 1]);
            if (dec_st_array[i + 26] != 0 && dec_st_array[i + 26 + 1] == 0)
              res[i] = 16 * getNum(dec_st_array[i + 26]);
            if (dec_st_array[i + 26] == 0 && dec_st_array[i + 26 + 1] != 0)
              res[i] = getNum(dec_st_array[i + 26 + 1]);
            if (dec_st_array[i + 26] == 0 && dec_st_array[i + 26 + 1] == 0)
              res[i] = 0;
          } else {
            if (dec_st_array[i + 26] != 0 && dec_st_array[i + 26 + 1] != 0)
              res[i / 2] = 16 * getNum(dec_st_array[i + 26]) + getNum(dec_st_array[i + 26 + 1]);
            if (dec_st_array[i + 26] != 0 && dec_st_array[i + 26 + 1] == 0)
              res[i / 2] = 16 * getNum(dec_st_array[i + 26]);
            if (dec_st_array[i + 26] == 0 && dec_st_array[i + 26 + 1] != 0)
              res[i / 2] = getNum(dec_st_array[i + 26 + 1]);
            if (dec_st_array[i + 26] == 0 && dec_st_array[i + 26 + 1] == 0)
              res[i / 2] = 0;
          }
        }
        String filenm = "/";
        for (int i = 0; i < 25; i++) {
          if (res[i] > 127)
            filenm += char(65 + (res[i] % 26));
          else
            filenm += char(97 + (res[i] % 26));
        }
        //Serial.println(filenm);
        gen_r = true;
        back_keys();
        dec_st = "";
        encrypt_string_with_tdes_aes_blf_srp(read_crd_bck + "0.00");
        rest_keys();
        //Serial.println(dec_st);
        if (read_file(filenm).equals("-1")) {
          performing_oper_inscr();
          write_to_file_with_overwrite(filenm, dec_st);
          tft.setTextSize(2);
          tft.fillScreen(0x155b);
          tft.setTextColor(0xffff, 0x155b);
          disp_centered_text("Account Created", 90);
          disp_centered_text("Successfully", 115);
          delay(3500);
          disp_centered_text("Press Either '#' or 'C'", 220);
          press_key_on_keyboard();
        } else {
          tft.setTextSize(2);
          tft.fillScreen(0xf961);
          tft.setTextColor(0xffff, 0xf961);
          disp_centered_text("Failed", 65);
          disp_centered_text("To Create An Account", 85);
          disp_centered_text("Account Already Exists", 115);
          disp_centered_text("Try Entering Different PIN", 150);
          delay(3500);
          disp_centered_text("Press Either '#' or 'C'", 220);
          press_key_on_keyboard();
        }
      } else {
        tft.setTextSize(2);
        tft.fillScreen(0xf961);
        tft.setTextColor(0xffff, 0xf961);
        disp_centered_text("Failed", 65);
        disp_centered_text("To Create An Account", 85);
        disp_centered_text("PINs Don't Match", 115);
        delay(3500);
        disp_centered_text("Press Either '#' or 'C'", 220);
        press_key_on_keyboard();
      }
    }
  }
  call_main_menu();
}

void view_account_balance() {
  tft.setTextSize(2);
  tft.fillScreen(0x155b);
  tft.setTextColor(0xffff);
  disp_centered_text("Approximate the card to", 90);
  disp_centered_text("the RFID reader", 110);
  disp_centered_text("Press 'C' to Cancel", 220);
  cont_to_next_step = true;
  get_input_from_arduino_uno_key_to_canc();
  for (int i = 0; i < 4; i++){
    read_cards[i] = read_card_rec_from_arduino[i];
  }
  if (cont_to_next_step == true) {
    for (int i = 0; i < 4; i++) {
      serp_key[i + 28] = read_cards[i];
    }
    tft.fillScreen(0x155b);
    disp_centered_text("Enter Your PIN", 60);
    disp_centered_text("* - Backspace", 180);
    disp_centered_text("# - Enter", 200);
    disp_centered_text("C - Cancel", 220);
    tft.fillRect(102, 135, 116, 32, 0x08c5);
    tft.setCursor(112, 145);
    tft.setTextColor(0xffff, 0x08c5);
    cont_t_nxt = false;
    bool setp1 = false;
    String pin1;
    while (setp1 != true) {

      code = keyboard.available();
      if (code > 0) {
        code = keyboard.read();
        code = keymap.remapKey(code);
        if (code > 0) {
          if ((code & 0xFF)) {

            if ((code & 0xFF) == 27) { // Esc
              cont_t_nxt = false;
              setp1 = true;
            } else if ((code & 0xFF) == 13) { // Enter
              cont_t_nxt = true;
              setp1 = true;
            } else if ((code & 0xFF) == 8) { // Backspace
              pin1.remove(pin1.length() - 1, 1);
              tft.fillRect(102, 135, 116, 32, 0x08c5);
            } else {
              if (pin1.length() < 8)
                pin1 += char(code & 0xFF);
            }

            tft.setCursor(112, 140);
            tft.setTextColor(0xffff, 0x08c5);
            String stars;
            for (int i = 0; i < pin1.length(); i++) {
              stars += "*";
            }
            tft.println(stars);
          }

        }
      }

      delayMicroseconds(400);
    }

    if (cont_t_nxt == true) {
      for (int i = 0; i < 4; i++) {
        serp_key[i + 28] = read_cards[i];
      }
      String read_card;
      for (int i = 0; i < 4; i++) {
        if (read_cards[i] < 16)
          read_card += "0";
        read_card += String(read_cards[i], HEX);
      }
      String read_crd_bck = read_card;
      read_card += pin1;
      //Serial.println(read_card);
      gen_r = false;
      back_keys();
      dec_st = "";
      encrypt_hash_with_tdes_aes_blf_srp(read_card);
      rest_keys();
      int dec_st_len = dec_st.length() + 1;
      char dec_st_array[dec_st_len];
      dec_st.toCharArray(dec_st_array, dec_st_len);
      //Serial.println(dec_st);
      byte res[25];
      for (int i = 0; i < 50; i += 2) {
        if (i == 0) {
          if (dec_st_array[i + 26] != 0 && dec_st_array[i + 26 + 1] != 0)
            res[i] = 16 * getNum(dec_st_array[i + 26]) + getNum(dec_st_array[i + 26 + 1]);
          if (dec_st_array[i + 26] != 0 && dec_st_array[i + 26 + 1] == 0)
            res[i] = 16 * getNum(dec_st_array[i + 26]);
          if (dec_st_array[i + 26] == 0 && dec_st_array[i + 26 + 1] != 0)
            res[i] = getNum(dec_st_array[i + 26 + 1]);
          if (dec_st_array[i + 26] == 0 && dec_st_array[i + 26 + 1] == 0)
            res[i] = 0;
        } else {
          if (dec_st_array[i + 26] != 0 && dec_st_array[i + 26 + 1] != 0)
            res[i / 2] = 16 * getNum(dec_st_array[i + 26]) + getNum(dec_st_array[i + 26 + 1]);
          if (dec_st_array[i + 26] != 0 && dec_st_array[i + 26 + 1] == 0)
            res[i / 2] = 16 * getNum(dec_st_array[i + 26]);
          if (dec_st_array[i + 26] == 0 && dec_st_array[i + 26 + 1] != 0)
            res[i / 2] = getNum(dec_st_array[i + 26 + 1]);
          if (dec_st_array[i + 26] == 0 && dec_st_array[i + 26 + 1] == 0)
            res[i / 2] = 0;
        }
      }
      String filenm = "/";
      for (int i = 0; i < 25; i++) {
        if (res[i] > 127)
          filenm += char(65 + (res[i] % 26));
        else
          filenm += char(97 + (res[i] % 26));
      }
      //Serial.println(filenm);
      gen_r = true;
      if (read_file(filenm).equals("-1")) {
        tft.setTextSize(2);
        tft.fillScreen(0xf961);
        tft.setTextColor(0xffff, 0xf961);
        disp_centered_text("Error", 65);
        disp_centered_text("Account Does Not Exist", 85);
        delay(2000);
        disp_centered_text("Press Either '#' or 'C'", 220);
        press_key_on_keyboard();
      } else {
        performing_oper_inscr();
        decrypt_string_with_TDES_AES_Blowfish_Serp(read_file(filenm));
        bool balance_integrity = verify_integrity();
        if (balance_integrity == true) {
          String extr_crd;
          for (int i = 0; i < 8; i++)
            extr_crd += dec_st.charAt(i);
          //Serial.println(dec_st);
          //Serial.println(extr_crd);
          //Serial.println(read_crd_bck);
          if (read_crd_bck.equals(extr_crd)) {
            String ublc;
            for (int i = 8; i < dec_st.length(); i++)
              ublc += dec_st.charAt(i);
            tft.fillScreen(0x155b);
            tft.setTextColor(0xffff, 0x155b);
            tft.setTextSize(2);
            disp_centered_text("Your balance is:", 45);
            tft.setTextSize(text_size_for_sale);
            disp_centered_text(ublc + space_and_currency, 80);
            delay(100);
            tft.setTextSize(2);
            disp_centered_text("Press Either '#' or 'C'", 220);
            press_key_on_keyboard();
          } else {
            tft.fillScreen(0x0000);
            tft.setTextSize(2);
            tft.setTextColor(five_six_five_red_color);
            disp_centered_text("System Error", 45);
            disp_centered_text("Record With Balance", 65);
            disp_centered_text("Doesn't Belong", 85);
            disp_centered_text("To This Card", 105);
            tft.setTextColor(0xffff);
            disp_centered_text("Please reboot", 180);
            disp_centered_text("the device", 200);
            disp_centered_text("and try again", 220);
            for (;;)
              delay(1000);
          }
        } else {
          tft.fillScreen(0x0000);
          tft.setTextSize(2);
          tft.setTextColor(five_six_five_red_color);
          disp_centered_text("System Error", 45);
          disp_centered_text("Integrity", 65);
          disp_centered_text("Verification", 85);
          disp_centered_text("Failed", 105);
          tft.setTextColor(0xffff);
          disp_centered_text("Please reboot", 180);
          disp_centered_text("the device", 200);
          disp_centered_text("and try again", 220);
          for (;;)
            delay(1000);
        }
      }
    }
  }
  call_main_menu();
}

void add_money_to_account() {
  clear_variables();
  tft.fillScreen(0x0000);
  tft.setTextColor(0xffff);
  tft.setTextSize(1);
  set_stuff_for_input("Enter Amount To Add");
  keyb_input();
  tft.fillScreen(0x0000);
  tft.setTextSize(2);
  tft.setTextColor(0xffff);
  disp_centered_text("Press '#'", 45);
  disp_centered_text("And Give The Device", 65);
  disp_centered_text("To The Client", 85);
  disp_centered_text("Press 'C' to Cancel", 220);
  cont_t_nxt = false;
  press_key_on_keyboard();
  if (cont_t_nxt == true) {
    //Serial.println(keyboard_input.toDouble());
    keyboard_input.replace(",", ".");
    double amnt_to_add = keyboard_input.toDouble();
    tft.setTextSize(2);
    tft.fillScreen(0x155b);
    tft.setTextColor(0xffff, 0x155b);
    disp_centered_text("Put " + String(amnt_to_add, 2) + space_and_currency + " in", 70);
    disp_centered_text("Approximate the card to", 120);
    disp_centered_text("the RFID reader", 140);
    disp_centered_text("Press 'C' to Cancel", 220);
    cont_to_next_step = true;
    get_input_from_arduino_uno_key_to_canc();
    for (int i = 0; i < 4; i++){
      read_cards[i] = read_card_rec_from_arduino[i];
    }
    if (cont_to_next_step == true) {
      for (int i = 0; i < 4; i++) {
        serp_key[i + 28] = read_cards[i];
      }
      tft.fillScreen(0x155b);
      disp_centered_text("Enter Your PIN", 60);
      disp_centered_text("* - Backspace", 180);
      disp_centered_text("# - Enter", 200);
      disp_centered_text("C - Cancel", 220);
      tft.fillRect(102, 135, 116, 32, 0x08c5);
      tft.setCursor(112, 145);
      tft.setTextColor(0xffff, 0x08c5);
      cont_t_nxt = false;
      bool setp1 = false;
      String pin1;
      while (setp1 != true) {

        code = keyboard.available();
        if (code > 0) {
          code = keyboard.read();
          code = keymap.remapKey(code);
          if (code > 0) {
            if ((code & 0xFF)) {

              if ((code & 0xFF) == 27) { // Esc
                cont_t_nxt = false;
                setp1 = true;
              } else if ((code & 0xFF) == 13) { // Enter
                cont_t_nxt = true;
                setp1 = true;
              } else if ((code & 0xFF) == 8) { // Backspace
                pin1.remove(pin1.length() - 1, 1);
                tft.fillRect(102, 135, 116, 32, 0x08c5);
              } else {
                if (pin1.length() < 8)
                  pin1 += char(code & 0xFF);
              }

              tft.setCursor(112, 140);
              tft.setTextColor(0xffff, 0x08c5);
              String stars;
              for (int i = 0; i < pin1.length(); i++) {
                stars += "*";
              }
              tft.println(stars);
            }

          }
        }

        delayMicroseconds(400);
      }

      if (cont_t_nxt == true) {
        for (int i = 0; i < 4; i++) {
          serp_key[i + 28] = read_cards[i];
        }
        String read_card;
        for (int i = 0; i < 4; i++) {
          if (read_cards[i] < 16)
            read_card += "0";
          read_card += String(read_cards[i], HEX);
        }
        String read_crd_bck = read_card;
        read_card += pin1;
        //Serial.println(read_card);
        gen_r = false;
        back_keys();
        dec_st = "";
        encrypt_hash_with_tdes_aes_blf_srp(read_card);
        rest_keys();
        int dec_st_len = dec_st.length() + 1;
        char dec_st_array[dec_st_len];
        dec_st.toCharArray(dec_st_array, dec_st_len);
        //Serial.println(dec_st);
        byte res[25];
        for (int i = 0; i < 50; i += 2) {
          if (i == 0) {
            if (dec_st_array[i + 26] != 0 && dec_st_array[i + 26 + 1] != 0)
              res[i] = 16 * getNum(dec_st_array[i + 26]) + getNum(dec_st_array[i + 26 + 1]);
            if (dec_st_array[i + 26] != 0 && dec_st_array[i + 26 + 1] == 0)
              res[i] = 16 * getNum(dec_st_array[i + 26]);
            if (dec_st_array[i + 26] == 0 && dec_st_array[i + 26 + 1] != 0)
              res[i] = getNum(dec_st_array[i + 26 + 1]);
            if (dec_st_array[i + 26] == 0 && dec_st_array[i + 26 + 1] == 0)
              res[i] = 0;
          } else {
            if (dec_st_array[i + 26] != 0 && dec_st_array[i + 26 + 1] != 0)
              res[i / 2] = 16 * getNum(dec_st_array[i + 26]) + getNum(dec_st_array[i + 26 + 1]);
            if (dec_st_array[i + 26] != 0 && dec_st_array[i + 26 + 1] == 0)
              res[i / 2] = 16 * getNum(dec_st_array[i + 26]);
            if (dec_st_array[i + 26] == 0 && dec_st_array[i + 26 + 1] != 0)
              res[i / 2] = getNum(dec_st_array[i + 26 + 1]);
            if (dec_st_array[i + 26] == 0 && dec_st_array[i + 26 + 1] == 0)
              res[i / 2] = 0;
          }
        }
        String filenm = "/";
        for (int i = 0; i < 25; i++) {
          if (res[i] > 127)
            filenm += char(65 + (res[i] % 26));
          else
            filenm += char(97 + (res[i] % 26));
        }
        //Serial.println(filenm);
        gen_r = true;
        if (read_file(filenm).equals("-1")) {
          tft.setTextSize(2);
          tft.fillScreen(0xf961);
          tft.setTextColor(0xffff, 0xf961);
          disp_centered_text("Error", 65);
          disp_centered_text("Account Does Not Exist", 85);
          delay(2000);
          disp_centered_text("Press Either '#' or 'C'", 220);
          press_key_on_keyboard();
        } else {
          performing_oper_inscr();
          decrypt_string_with_TDES_AES_Blowfish_Serp(read_file(filenm));
          bool balance_integrity = verify_integrity();
          if (balance_integrity == true) {
            String extr_crd;
            for (int i = 0; i < 8; i++)
              extr_crd += dec_st.charAt(i);
            //Serial.println(dec_st);
            //Serial.println(extr_crd);
            //Serial.println(read_crd_bck);
            if (read_crd_bck.equals(extr_crd)) {
              String ublc;
              for (int i = 8; i < dec_st.length(); i++)
                ublc += dec_st.charAt(i);
              double new_bal = ublc.toDouble() + amnt_to_add;
              gen_r = true;
              back_keys();
              dec_st = "";
              //Serial.println(read_crd_bck);
              //Serial.println(extr_crd);
              //Serial.println(read_crd_bck + String(new_bal, 2));
              encrypt_string_with_tdes_aes_blf_srp(read_crd_bck + String(new_bal, 2));
              rest_keys();
              write_to_file_with_overwrite(filenm, dec_st);
              tft.fillScreen(0x155b);
              tft.setTextColor(0xffff, 0x155b);
              tft.setTextSize(3);
              disp_centered_text("Done!", 45);
              delay(100);
              tft.setTextSize(2);
              disp_centered_text("Press Either '#' or 'C'", 220);
              press_key_on_keyboard();
            } else {
              tft.fillScreen(0x0000);
              tft.setTextSize(2);
              tft.setTextColor(five_six_five_red_color);
              disp_centered_text("System Error", 45);
              disp_centered_text("Record With Balance", 65);
              disp_centered_text("Doesn't Belong", 85);
              disp_centered_text("To This Card", 105);
              tft.setTextColor(0xffff);
              disp_centered_text("Please reboot", 180);
              disp_centered_text("the device", 200);
              disp_centered_text("and try again", 220);
              for (;;)
                delay(1000);
            }
          } else {
            tft.fillScreen(0x0000);
            tft.setTextSize(2);
            tft.setTextColor(five_six_five_red_color);
            disp_centered_text("System Error", 45);
            disp_centered_text("Integrity", 65);
            disp_centered_text("Verification", 85);
            disp_centered_text("Failed", 105);
            tft.setTextColor(0xffff);
            disp_centered_text("Please reboot", 180);
            disp_centered_text("the device", 200);
            disp_centered_text("and try again", 220);
            for (;;)
              delay(1000);
          }
        }
      }
    }
  }
}

void reduce_account_balance() {
  clear_variables();
  tft.fillScreen(0x0000);
  tft.setTextColor(0xffff);
  tft.setTextSize(1);
  set_stuff_for_input("Enter Sale Amount");
  keyb_input();
  tft.fillScreen(0x0000);
  tft.setTextSize(2);
  tft.setTextColor(0xffff);
  disp_centered_text("Press '#'", 45);
  disp_centered_text("And Give The Device", 65);
  disp_centered_text("To The Client", 85);
  disp_centered_text("Press 'C' to Cancel", 220);
  cont_t_nxt = false;
  press_key_on_keyboard();
  if (cont_t_nxt == true) {
    //Serial.println(keyboard_input.toDouble());
    keyboard_input.replace(",", ".");
    double amnt_to_reduce = keyboard_input.toDouble();
    tft.setTextSize(2);
    tft.fillScreen(0x155b);
    tft.setTextColor(0xffff, 0x155b);
    disp_centered_text("Sale", 30);
    disp_centered_text(String(amnt_to_reduce, 2) + space_and_currency, 70);
    disp_centered_text("Approximate the card to", 120);
    disp_centered_text("the RFID reader", 140);
    disp_centered_text("Press 'C' to Cancel", 220);

    cont_to_next_step = true;
    get_input_from_arduino_uno_key_to_canc();
    for (int i = 0; i < 4; i++){
      read_cards[i] = read_card_rec_from_arduino[i];
    }
    if (cont_to_next_step == true) {
      for (int i = 0; i < 4; i++) {
        serp_key[i + 28] = read_cards[i];
      }
      tft.fillScreen(0x155b);
      disp_centered_text("Enter Your PIN", 60);
      disp_centered_text("* - Backspace", 180);
      disp_centered_text("# - Enter", 200);
      disp_centered_text("C - Cancel", 220);
      tft.fillRect(102, 135, 116, 32, 0x08c5);
      tft.setCursor(112, 145);
      tft.setTextColor(0xffff, 0x08c5);
      cont_t_nxt = false;
      bool setp1 = false;
      String pin1;
      while (setp1 != true) {

        code = keyboard.available();
        if (code > 0) {
          code = keyboard.read();
          code = keymap.remapKey(code);
          if (code > 0) {
            if ((code & 0xFF)) {

              if ((code & 0xFF) == 27) { // Esc
                cont_t_nxt = false;
                setp1 = true;
              } else if ((code & 0xFF) == 13) { // Enter
                cont_t_nxt = true;
                setp1 = true;
              } else if ((code & 0xFF) == 8) { // Backspace
                pin1.remove(pin1.length() - 1, 1);
                tft.fillRect(102, 135, 116, 32, 0x08c5);
              } else {
                if (pin1.length() < 8)
                  pin1 += char(code & 0xFF);
              }

              tft.setCursor(112, 140);
              tft.setTextColor(0xffff, 0x08c5);
              String stars;
              for (int i = 0; i < pin1.length(); i++) {
                stars += "*";
              }
              tft.println(stars);
            }

          }
        }

        delayMicroseconds(400);
      }

      if (cont_t_nxt == true) {
        for (int i = 0; i < 4; i++) {
          serp_key[i + 28] = read_cards[i];
        }
        String read_card;
        for (int i = 0; i < 4; i++) {
          if (read_cards[i] < 16)
            read_card += "0";
          read_card += String(read_cards[i], HEX);
        }
        String read_crd_bck = read_card;
        read_card += pin1;
        //Serial.println(read_card);
        gen_r = false;
        back_keys();
        dec_st = "";
        encrypt_hash_with_tdes_aes_blf_srp(read_card);
        rest_keys();
        int dec_st_len = dec_st.length() + 1;
        char dec_st_array[dec_st_len];
        dec_st.toCharArray(dec_st_array, dec_st_len);
        //Serial.println(dec_st);
        byte res[25];
        for (int i = 0; i < 50; i += 2) {
          if (i == 0) {
            if (dec_st_array[i + 26] != 0 && dec_st_array[i + 26 + 1] != 0)
              res[i] = 16 * getNum(dec_st_array[i + 26]) + getNum(dec_st_array[i + 26 + 1]);
            if (dec_st_array[i + 26] != 0 && dec_st_array[i + 26 + 1] == 0)
              res[i] = 16 * getNum(dec_st_array[i + 26]);
            if (dec_st_array[i + 26] == 0 && dec_st_array[i + 26 + 1] != 0)
              res[i] = getNum(dec_st_array[i + 26 + 1]);
            if (dec_st_array[i + 26] == 0 && dec_st_array[i + 26 + 1] == 0)
              res[i] = 0;
          } else {
            if (dec_st_array[i + 26] != 0 && dec_st_array[i + 26 + 1] != 0)
              res[i / 2] = 16 * getNum(dec_st_array[i + 26]) + getNum(dec_st_array[i + 26 + 1]);
            if (dec_st_array[i + 26] != 0 && dec_st_array[i + 26 + 1] == 0)
              res[i / 2] = 16 * getNum(dec_st_array[i + 26]);
            if (dec_st_array[i + 26] == 0 && dec_st_array[i + 26 + 1] != 0)
              res[i / 2] = getNum(dec_st_array[i + 26 + 1]);
            if (dec_st_array[i + 26] == 0 && dec_st_array[i + 26 + 1] == 0)
              res[i / 2] = 0;
          }
        }
        String filenm = "/";
        for (int i = 0; i < 25; i++) {
          if (res[i] > 127)
            filenm += char(65 + (res[i] % 26));
          else
            filenm += char(97 + (res[i] % 26));
        }
        //Serial.println(filenm);
        gen_r = true;
        if (read_file(filenm).equals("-1")) {
          tft.setTextSize(2);
          tft.fillScreen(0xf961);
          tft.setTextColor(0xffff, 0xf961);
          disp_centered_text("Error", 65);
          disp_centered_text("Account Does Not Exist", 85);
          delay(2000);
          disp_centered_text("Press Either '#' or 'C'", 220);
          press_key_on_keyboard();
        } else {
          performing_oper_inscr();
          decrypt_string_with_TDES_AES_Blowfish_Serp(read_file(filenm));
          bool balance_integrity = verify_integrity();
          if (balance_integrity == true) {
            String extr_crd;
            for (int i = 0; i < 8; i++)
              extr_crd += dec_st.charAt(i);
            //Serial.println(dec_st);
            //Serial.println(extr_crd);
            //Serial.println(read_crd_bck);
            if (read_crd_bck.equals(extr_crd)) {
              String ublc;
              for (int i = 8; i < dec_st.length(); i++)
                ublc += dec_st.charAt(i);
              double new_bal = ublc.toDouble() - amnt_to_reduce;
              gen_r = true;
              back_keys();
              dec_st = "";
              if (new_bal >= 0) {
                encrypt_string_with_tdes_aes_blf_srp(read_crd_bck + String(new_bal, 2));
                rest_keys();
                write_to_file_with_overwrite(filenm, dec_st);
                tft.fillScreen(0x155b);
                tft.setTextColor(0xffff, 0x155b);
                tft.setTextSize(3);
                disp_centered_text("Done!", 45);
                delay(100);
                tft.setTextSize(2);
                disp_centered_text("Press Either '#' or 'C'", 220);
                press_key_on_keyboard();
              } else {
                tft.setTextSize(2);
                tft.fillScreen(0xf17f);
                tft.setTextColor(0xffff, 0xf17f);
                disp_centered_text("Not enough money in the", 90);
                disp_centered_text("account to complete the", 110);
                disp_centered_text("transaction", 130);
                delay(2000);
                disp_centered_text("Press Either '#' or 'C'", 220);
                press_key_on_keyboard();
              }
            } else {
              tft.fillScreen(0x0000);
              tft.setTextSize(2);
              tft.setTextColor(five_six_five_red_color);
              disp_centered_text("System Error", 45);
              disp_centered_text("Record With Balance", 65);
              disp_centered_text("Doesn't Belong", 85);
              disp_centered_text("To This Card", 105);
              tft.setTextColor(0xffff);
              disp_centered_text("Please reboot", 180);
              disp_centered_text("the device", 200);
              disp_centered_text("and try again", 220);
              for (;;)
                delay(1000);
            }
          } else {
            tft.fillScreen(0x0000);
            tft.setTextSize(2);
            tft.setTextColor(five_six_five_red_color);
            disp_centered_text("System Error", 45);
            disp_centered_text("Integrity", 65);
            disp_centered_text("Verification", 85);
            disp_centered_text("Failed", 105);
            tft.setTextColor(0xffff);
            disp_centered_text("Please reboot", 180);
            disp_centered_text("the device", 200);
            disp_centered_text("and try again", 220);
            for (;;)
              delay(1000);
          }
        }
      }
    }
  }
}

void performing_oper_inscr(){
  tft.setTextSize(1);
  tft.setTextColor(0xffff);
  tft.setCursor(0, 10);
  tft.println("Performing operation...");
  tft.setCursor(0, 22);
  tft.println("Please wait for a while");
}

void Wifi_Init() {
  tft.setTextSize(1);
  tft.setTextColor(0xffff);
  tft.setCursor(0, 10);
  tft.println("Connecting to Wi-Fi");
  tft.setCursor(0, 22);
  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
  while (WiFi.status() != WL_CONNECTED) {
    delay(300);
    tft.print("#");
  }
}

void firebase_init() {
  byte sdown = 150;
  tft.fillScreen(0x0000);
  disp_centered_text("Initializing Firebase", 10);
  // configure firebase API Key
  config.api_key = API_KEY;
  // configure firebase realtime database url
  config.database_url = DATABASE_URL;
  // Enable WiFi reconnection 
  Firebase.reconnectWiFi(true);
  if (Firebase.signUp( & config, & auth, "", "")) {
    isAuthenticated = true;
    fuid = auth.token.uid.c_str();
  } else {
    delay(40);
    isAuthenticated = false;
    tft.fillScreen(0x0000);
    tft.setTextColor(0xf800);
    disp_centered_text("Failed To Initialize", 5);
    disp_centered_text("FIrebase", 20);
    disp_centered_text("Please reboot", sdown + 30);
    disp_centered_text("the device", sdown + 40);
    disp_centered_text("and try again", sdown + 50);
    while(1){
      delay(1000);
    }
  }
  // Assign the callback function for the long running token generation task, see addons/TokenHelper.h
  config.token_status_callback = tokenStatusCallback;
  // Initialise the firebase library
  Firebase.begin( & config, & auth);
}

void setup(void) {
  tft.begin();
  tft.fillScreen(0x0000);
  tft.setRotation(1);
  Wifi_Init();
  firebase_init();
  mvng_bc.createSprite(312, 61);
  mvng_bc.setColorDepth(16);
  gen_r = true;
  keyboard.begin(DATAPIN, IRQPIN);
  keyboard.setNoBreak(1);
  keyboard.setNoRepeat(1);
  keymap.selectMap((char * )
    "US");
  menu_pos = 0;
  m = 2; // Set AES to 256-bit mode
  Serial.begin(115200);
  mySerial.begin(4800);
  lock_scr_without_rfid();
  continue_to_unlock();
  back_def_serp_k();
}

void loop() {
  for (int i = 0; i < 312; i++) {
    for (int j = 0; j < 61; j++) {
      if (khadash_pay_icon[i][j] == 1)
        mvng_bc.drawPixel(i, j, Frankfurt[(i + 4 + k) % 320][j + 98]);
    }
  }
  mvng_bc.pushSprite(4, 10, TFT_TRANSPARENT);

  if (keyboard.available()) {
    //Serial.println(int(c));
    c = keyboard.read();
    rest_def_serp_k();
    if (c == 279 || c == 56)
      menu_pos--;

    if (c == 280 || c == 48)
      menu_pos++;

    if (menu_pos < 0)
      menu_pos = 4;

    if (menu_pos > 4)
      menu_pos = 0;

    if ((c & 0xFF) == 30)
      enter_operator_password_to_continue(menu_pos);

    if (c == 61) {
      lock_screen_keyboard();
    }
    disp_menu();

  }
  delayMicroseconds(400);
  k++;
}
