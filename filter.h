#ifndef _FILTER_H_
#define _FILTER_H_

class INumberFilter {
public:
	virtual ~INumberFilter() {};
	virtual bool IsDropULL(unsigned long long value) = 0;
	virtual void SetDefault(bool retain) = 0;
	virtual void AddRuleEqualULL(bool retain, unsigned long long value) = 0;
	virtual void AddRuleGreaterThanULL(bool retain, unsigned long long value, bool include_equal) = 0;
	virtual void AddRuleLessThanULL(bool retain, unsigned long long value, bool include_equal) = 0;
	virtual void AddRuleBetweenULL(bool retain,
		unsigned long long left_value, bool include_left_equal,
		unsigned long long right_value, bool include_right_equal) = 0;
};

INumberFilter* MakeNumberFilter();
void DestroyNumberFilter(INumberFilter* filter);

#endif// _FILTER_H_