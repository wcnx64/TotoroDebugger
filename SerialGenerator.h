#ifndef _SERIAL_GENERATOR_H_
#define _SERIAL_GENERATOR_H_

#define INTEGER_SERIAL_AUTO_START_SHUTDOWN

#define INTEGER_SERIAL_CLASS_VMP_BLOCK 1

class IGlobalIntegerSerialGenerator {
public:
    static bool Register(unsigned long class_id, unsigned long long serial_start, bool locked_operation);
    static unsigned long long Generate(unsigned long class_id);
    static unsigned long long Reset(unsigned long class_id);
#ifndef INTEGER_SERIAL_AUTO_START_SHUTDOWN
    static bool Start(unsigned long class_id, unsigned long long serial_start, bool locked_operation);
    static void Shutdown();
#endif // INTEGER_SERIAL_AUTO_START_SHUTDOWN
protected:
    IGlobalIntegerSerialGenerator();
private:
    IGlobalIntegerSerialGenerator(const IGlobalIntegerSerialGenerator&) = delete;
    IGlobalIntegerSerialGenerator& operator = (IGlobalIntegerSerialGenerator&) = delete;
};

#endif // _SERIAL_GENERATOR_H_