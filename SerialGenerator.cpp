#include <map>
#include "SerialGenerator.h"

typedef struct GlobalIntegerSerialInfo {
    unsigned long      class_id;         // for potential convenience
    unsigned long long serial_start;
    unsigned long long serial;
    bool               locked_operation; // lock / unlock when generating serial
    volatile char      lock;             // value for spinlock
} GlobalIntegerSerialInfo, * PGlobalIntegerSerialInfo;

class GlobalIntegerSerialGenerator : public IGlobalIntegerSerialGenerator {
public:
    bool Register(
        unsigned long class_id,
        unsigned long long serial_start,
        bool locked_operation) {
        GlobalIntegerSerialInfo serial_info;
        serial_info.class_id = class_id;
        serial_info.serial = serial_info.serial_start = serial_start;
        serial_info.locked_operation = locked_operation;
        serial_info.lock = 0;
        try {
            serials[class_id] = serial_info;
            return true;
        }
        catch (...) {
            return false;
        }
    }
    unsigned long long Generate(unsigned long class_id) {
        GlobalIntegerSerialInfo& serial_info = serials[class_id];
        // lock
        if (serial_info.locked_operation) {
            while (_InterlockedCompareExchange8(&serial_info.lock, 1, 0) == 1);
        }
        serial_info.serial++;
        unsigned long long result = serial_info.serial;
        // unlock
        serial_info.lock = 0; // fastest way, no side effect
        return result;
    }
    unsigned long long Reset(unsigned long class_id) {
        GlobalIntegerSerialInfo& serial_info = serials[class_id];
        // lock
        if (serial_info.locked_operation) {
            while (_InterlockedCompareExchange8(&serial_info.lock, 1, 0) == 1);
        }
        serial_info.serial = serial_info.serial_start;
        unsigned long long result = serial_info.serial;
        // unlock
        serial_info.lock = 0; // fastest way, no side effect
        return result;
    }

    // the following functions are safe singleton utilities

    static GlobalIntegerSerialGenerator& GetInstance() {
        if (inst == nullptr) {
            inst = new GlobalIntegerSerialGenerator();
        }
        return *inst;
    }
    static bool Start() { // for safe initialization
#ifdef INTEGER_SERIAL_AUTO_START_SHUTDOWN
        GlobalIntegerSerialGenerator::GetInstance();
        return true;
#else
        if (inst == nullptr) {
            inst = new(std::nothrow) GlobalIntegerSerialGenerator();
        }
        return inst ? true : false;
#endif
    }
    static void Shutdown() {
        if (inst) {
            delete inst;
            inst = nullptr;
        }
    }
private:
    GlobalIntegerSerialGenerator() {};
    ~GlobalIntegerSerialGenerator() { serials.clear(); };
    GlobalIntegerSerialGenerator(GlobalIntegerSerialGenerator&) = delete;
    GlobalIntegerSerialGenerator& operator = (GlobalIntegerSerialGenerator&) = delete;
protected:
    static GlobalIntegerSerialGenerator* inst;
    std::map<unsigned long, GlobalIntegerSerialInfo> serials;
};
GlobalIntegerSerialGenerator* GlobalIntegerSerialGenerator::inst = nullptr;

// the initializer is used to avoid the memory leak caused by reentry the singleton's GetInstance method
// and to avoid forgetting the Shutdown
class GlobalIntegerSerialGeneratorInitializer {
public:
    GlobalIntegerSerialGeneratorInitializer() {
        // GlobalIntegerSerialGenerator::GetInstance();
        GlobalIntegerSerialGenerator::Start();
    }
    ~GlobalIntegerSerialGeneratorInitializer() {
        GlobalIntegerSerialGenerator::Shutdown();
    }
};
static GlobalIntegerSerialGeneratorInitializer g_globalIntegerSerialGeneratorInitializer;

// common interfaces
IGlobalIntegerSerialGenerator::IGlobalIntegerSerialGenerator() {};

bool IGlobalIntegerSerialGenerator::Register(unsigned long class_id, unsigned long long serial_start, bool locked_operation) {
    return GlobalIntegerSerialGenerator::GetInstance().Register(class_id, serial_start, locked_operation);
}

unsigned long long IGlobalIntegerSerialGenerator::Generate(unsigned long class_id) {
    return GlobalIntegerSerialGenerator::GetInstance().Generate(class_id);
}

unsigned long long IGlobalIntegerSerialGenerator::Reset(unsigned long class_id) {
    return GlobalIntegerSerialGenerator::GetInstance().Reset(class_id);
}
