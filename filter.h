#ifndef _FILTER_H_
#define _FILTER_H_

/// <summary>
/// filter according to numerical relations
/// </summary>
class INumberFilter {
public:
	virtual ~INumberFilter() {};
	/// <summary>
	/// reset
	/// </summary>
	virtual void Reset() = 0;
	/// <summary>
	/// Check if the holder of the value is to be dropped according to the rules.
	/// For example, if we set only [3,5] is retained,
	/// then the holder of value 6 is to be dropped (return true),
	/// and return false if value == 4.
	/// </summary>
	/// <param name="value">the value to be checked</param>
	/// <returns>drop or not</returns>
	virtual bool IsDropULL(unsigned long long value) = 0;
	/// <summary>
	/// set the default operation to a value, that is, to retain it or not.
	/// </summary>
	/// <param name="retain">retain it or not</param>
	virtual void SetDefault(bool retain) = 0;
	/// <summary>
	/// add a rule for values that equal the parameter "value"
	/// </summary>
	/// <param name="retain">retain it or not</param>
	/// <param name="value">value</param>
	virtual void AddRuleEqualULL(bool retain, unsigned long long value) = 0;
	/// <summary>
	/// add a rule for values that are greater than the parameter "value"
	/// when include_equal is true, the relation is "being greater than or equal to".
	/// </summary>
	/// <param name="retain">retain it or not</param>
	/// <param name="value">value</param>
	/// <param name="include_equal">true if "greater than or equal to" is used</param>
	virtual void AddRuleGreaterThanULL(bool retain, unsigned long long value, bool include_equal) = 0;
	/// <summary>
	/// add a rule for values that are less than the parameter "value"
	/// when include_equal is true, the relation is "being less than or equal to".
	/// </summary>
	/// <param name="retain">retain it or not</param>
	/// <param name="value">value</param>
	/// <param name="include_equal">true if "less than or equal to" is used</param>
	virtual void AddRuleLessThanULL(bool retain, unsigned long long value, bool include_equal) = 0;
	/// <summary>
	/// add a rule for values within a range.
	/// include_left_equal and include_right_equal are set to control
	/// if the values that are equal to the boundaries are included.
	/// </summary>
	/// <param name="retain">retain it or not</param>
	/// <param name="left_value">the smaller boundary of the range</param>
	/// <param name="include_left_equal">whether a value equaling the smaller boundary is included or not</param>
	/// <param name="right_value">the bigger boundary of the range</param>
	/// <param name="include_right_equal">whether a value equaling the bigger boundary is included or not</param>
	virtual void AddRuleBetweenULL(bool retain,
		unsigned long long left_value, bool include_left_equal,
		unsigned long long right_value, bool include_right_equal) = 0;
};

/// <summary>
/// create a NumberFilter
/// </summary>
/// <returns>the interface of the NumberFilter</returns>
INumberFilter* CreateNumberFilter();

/// <summary>
/// destroy a NumberFileter
/// </summary>
/// <param name="filter">the interface of the NumberFilter</param>
void DestroyNumberFilter(INumberFilter* filter);

#endif// _FILTER_H_