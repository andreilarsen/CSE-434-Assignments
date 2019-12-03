#ifndef OPCODE_DEFINES_H
#define OPCODE_DEFINES_H

#define OPCODE_SESSION_RESET                0x80
#define OPCODE_MUST_LOGIN_FIRST             0x01
#define OPCODE_LOGIN                        0x82
#define OPCODE_SUCCESSFUL_LOGIN_ACK         0x03
#define OPCODE_FAILED_LOGIN_ACK             0x84
#define OPCODE_SUBSCRIBE                    0x05
#define OPCODE_SUCCESSFUL_SUBSCRIBE_ACK     0x86
#define OPCODE_FAILED_SUBSCRIBE_ACK         0x07
#define OPCODE_UNSUBSCRIBE                  0x88
#define OPCODE_SUCCESSFUL_UNSUBSCRIBE_ACK   0x09
#define OPCODE_FAILED_UNSUBSCRIBE_ACK       0x8A
#define OPCODE_POST                         0x0B
#define OPCODE_POST_ACK                     0x8C
#define OPCODE_FORWARD                      0x0D
#define OPCODE_FORWARD_ACK                  0x8E
#define OPCODE_RETRIEVE                     0x0F
#define OPCODE_RETRIEVE_ACK                 0x80
#define OPCODE_END_OF_RETRIEVE_ACK          0x81
#define OPCODE_LOGOUT                       0x82
#define OPCODE_LOGOUT_ACK                   0x83

#endif  // OPCODE_DEFINES_H