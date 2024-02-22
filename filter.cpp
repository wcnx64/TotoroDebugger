#include <vector>
#include "filter.h"

typedef bool (*NumberFilterRuleCompareFunc)(
	unsigned long long value,
	unsigned long long cmp_left_value,
	unsigned long long cmp_right_value);

typedef struct NumberFilterRule {
	bool                        retain;
	unsigned long long          left_value;
	unsigned long long          right_value;
	NumberFilterRuleCompareFunc compare_func; // return true when equal or being in the range
} NumberFilterRule, *PNumberFilterRule;

class NumberFilter : public INumberFilter {
public:
	NumberFilter();
	~NumberFilter();
	void Reset();
	bool IsDropULL(unsigned long long value);
	void SetDefault(bool retain);
	void AddRuleEqualULL(bool retain, unsigned long long value);
	void AddRuleGreaterThanULL(bool retain, unsigned long long value, bool include_equal);
	void AddRuleLessThanULL(bool retain, unsigned long long value, bool include_equal);
	void AddRuleBetweenULL(bool retain,
		unsigned long long left_value, bool include_left_equal,
		unsigned long long right_value, bool include_right_equal);
protected:
	std::vector<NumberFilterRule> rules;
	bool default_retain;
};

NumberFilter::NumberFilter() : default_retain(true) {
}

NumberFilter::~NumberFilter() {
	this->Reset();
}

void NumberFilter::Reset() {
	this->rules.clear();
}

bool NumberFilter::IsDropULL(unsigned long long value) {
	for (std::vector<NumberFilterRule>::iterator i = rules.begin(); i != rules.end(); i++) {
		// if ret == retain then retain else drop
		if ((*i).compare_func &&
			((*i).compare_func(value, (*i).left_value, (*i).right_value) ^ (*i).retain)) {
			return true;
		}
	}
	return false;
}

void NumberFilter::SetDefault(bool retain) {
	this->default_retain = retain;
}

void NumberFilter::AddRuleEqualULL(bool retain, unsigned long long value) {
	NumberFilterRule rule = { 0 };
	rule.retain = retain;
	rule.left_value = value;
	rule.compare_func = [](unsigned long long value,
		unsigned long long cmp_left_value,
		unsigned long long cmp_right_value) {
			return value == cmp_left_value;
	};
	rules.push_back(rule);
}

void NumberFilter::AddRuleGreaterThanULL(bool retain, unsigned long long value, bool include_equal) {
	NumberFilterRule rule = { 0 };
	rule.retain = retain;
	rule.left_value = value;
	if (include_equal) {
		rule.compare_func = [](unsigned long long value,
			unsigned long long cmp_left_value,
			unsigned long long cmp_right_value) {
				return value >= cmp_left_value;
		};
	}
	else {
		rule.compare_func = [](unsigned long long value,
			unsigned long long cmp_left_value,
			unsigned long long cmp_right_value) {
				return value > cmp_left_value;
		};
	}
	rules.push_back(rule);
}

void NumberFilter::AddRuleLessThanULL(bool retain, unsigned long long value, bool include_equal) {
	NumberFilterRule rule = { 0 };
	rule.retain = retain;
	rule.right_value = value;
	if (include_equal) {
		rule.compare_func = [](unsigned long long value,
			unsigned long long cmp_left_value,
			unsigned long long cmp_right_value) {
				return value <= cmp_right_value;
		};
	}
	else {
		rule.compare_func = [](unsigned long long value,
			unsigned long long cmp_left_value,
			unsigned long long cmp_right_value) {
				return value < cmp_right_value;
		};
	}
	rules.push_back(rule);
}

void NumberFilter::AddRuleBetweenULL(bool retain,
	unsigned long long left_value, bool include_left_equal,
	unsigned long long right_value, bool include_right_equal) {
	NumberFilterRule rule = { 0 };
	rule.retain = retain;
	rule.left_value = left_value;
	rule.right_value = right_value;
	if (include_left_equal) {
		if (include_right_equal) {
			rule.compare_func = [](unsigned long long value,
				unsigned long long cmp_left_value,
				unsigned long long cmp_right_value) {
					return value >= cmp_left_value && value <= cmp_right_value;
			};
		}
		else {
			rule.compare_func = [](unsigned long long value,
				unsigned long long cmp_left_value,
				unsigned long long cmp_right_value) {
					return value >= cmp_left_value && value < cmp_right_value;
			};
		}
	}
	else {
		if (include_right_equal) {
			rule.compare_func = [](unsigned long long value,
				unsigned long long cmp_left_value,
				unsigned long long cmp_right_value) {
					return value > cmp_left_value && value <= cmp_right_value;
			};
		}
		else {
			rule.compare_func = [](unsigned long long value,
				unsigned long long cmp_left_value,
				unsigned long long cmp_right_value) {
					return value > cmp_left_value && value < cmp_right_value;
			};
		}
	}
	rules.push_back(rule);
}


INumberFilter* CreateNumberFilter() {
	return new(std::nothrow) NumberFilter();
}

void DestroyNumberFilter(INumberFilter* filter) {
	if (filter)
		delete filter;
}
