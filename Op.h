#ifndef _OP_H_
#define _OP_H_

const char* TranslateOperator(unsigned long Opcode);
const char* TranslateRegister(unsigned long Reg);

unsigned long long CalculateOpRR(unsigned long Opcode, unsigned long long R1, unsigned long long R2);
bool IsNotByValue(unsigned long long V1, unsigned long long V2, unsigned long* Width);

#endif // _OP_H_
