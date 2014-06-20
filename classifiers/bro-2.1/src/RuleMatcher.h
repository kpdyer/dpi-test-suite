#ifndef sigs_h
#define sigs_h

#include <limits.h>

#include "BroString.h"
#include "List.h"
#include "RE.h"
#include "Net.h"
#include "Sessions.h"
#include "IntSet.h"
#include "util.h"
#include "Rule.h"
#include "RuleAction.h"
#include "RuleCondition.h"

//#define MATCHER_PRINT_STATS

extern int rule_bench;

// Parser interface:

extern void rules_error(const char* msg);
extern void rules_error(const char* msg, const char* addl);
extern void rules_error(Rule* id, const char* msg);
extern int rules_lex(void);
extern int rules_parse(void);
extern "C" int rules_wrap(void);
extern FILE* rules_in;
extern int rules_line_number;
extern const char* current_rule_file;

class RuleMatcher;
extern RuleMatcher* rule_matcher;

class Analyzer;
class PIA;

// RuleHdrTest and associated things:

// Given a header expression like "ip[offset:len] & mask = val", we parse
// it into a Range and a MaskedValue.
struct Range {
	uint32 offset;
	uint32 len;
};

struct MaskedValue {
	uint32 val;
	uint32 mask;
};

declare(PList, MaskedValue);
typedef PList(MaskedValue) maskedvalue_list;

typedef PList(char) string_list;

declare(PList, BroString);
typedef PList(BroString) bstr_list;

// Get values from Bro's script-level variables.
extern void id_to_maskedvallist(const char* id, maskedvalue_list* append_to);
extern char* id_to_str(const char* id);
extern uint32 id_to_uint(const char* id);

class RuleHdrTest {
public:
	enum Comp { LE, GE, LT, GT, EQ, NE };
	enum Prot { NOPROT, IP, ICMP, TCP, UDP };

	RuleHdrTest(Prot arg_prot, uint32 arg_offset, uint32 arg_size,
			Comp arg_comp, maskedvalue_list* arg_vals);
	~RuleHdrTest();

	void PrintDebug();

private:
	// The constructor does not copy those attributes which are set
	// by RuleMatcher::BuildRulesTree() (see below).
	RuleHdrTest(RuleHdrTest& h);
		// should be const, but lists don't have const version

	// Likewise, the operator== checks only for same test semantics.
	bool operator==(const RuleHdrTest& h);

	Prot prot;
	Comp comp;
	maskedvalue_list* vals;
	uint32 offset;
	uint32 size;

	uint32 id;	// For debugging, each HdrTest gets an unique ID
	static uint32 idcounter;

	// The following are all set by RuleMatcher::BuildRulesTree().
	friend class RuleMatcher;

	struct PatternSet {
		PatternSet() {}

		// If we're above the 'RE_level' (see RuleMatcher), this
		// expr contains all patterns on this node. If we're on
		// 'RE_level', it additionally contains all patterns
		// of any of its children.
		Specific_RE_Matcher* re;

		// All the patterns and their rule indices.
		string_list patterns;
		int_list ids;	// (only needed for debugging)
	};

	declare(PList, PatternSet);
	typedef PList(PatternSet) pattern_set_list;
	pattern_set_list psets[Rule::TYPES];

	// List of rules belonging to this node.
	Rule* pattern_rules;	// rules w/ at least one pattern of any type
	Rule* pure_rules;	// rules containing no patterns at all

	IntSet* ruleset;	// set of all rules belonging to this node
				// (for fast membership test)

	RuleHdrTest* sibling;	// linkage within HdrTest tree
	RuleHdrTest* child;

	int level;	// level within the tree
};

declare(PList, RuleHdrTest);
typedef PList(RuleHdrTest) rule_hdr_test_list;

// RuleEndpointState keeps the per-stream matching state of one
// connection endpoint.
class RuleEndpointState {
public:
	~RuleEndpointState();

	Analyzer* GetAnalyzer()	const	{ return analyzer; }
	bool IsOrig()		{ return is_orig; }

	// For flipping roles.
	void FlipIsOrig()	{ is_orig = ! is_orig; }

	// Returns the size of the first non-empty chunk of
	//   data feed into the RULE_PAYLOAD matcher.
	// Returns 0 zero iff only empty chunks have been fed.
	// Returns -1 if no chunk has been fed yet at all.
	int PayloadSize()	{ return payload_size; }

	::PIA* PIA() const	{ return pia; }

private:
	friend class RuleMatcher;

	// Constructor is private; use RuleMatcher::InitEndpoint()
	// for creating an instance.
	RuleEndpointState(Analyzer* arg_analyzer, bool arg_is_orig,
			  RuleEndpointState* arg_opposite, ::PIA* arg_PIA);

	struct Matcher {
		RE_Match_State* state;
		Rule::PatternType type;
	};

	declare(PList, Matcher);
	typedef PList(Matcher) matcher_list;

	bool is_orig;
	Analyzer* analyzer;
	RuleEndpointState* opposite;
	::PIA* pia;

	matcher_list matchers;
	rule_hdr_test_list hdr_tests;

	// The follow tracks which rules for which all patterns have matched,
	// and in a parallel list the (first instance of the) corresponding
	// matched text.
	rule_list matched_by_patterns;
	bstr_list matched_text;

	int payload_size;

	int_list matched_rules;		// Rules for which all conditions have matched
};


// RuleMatcher is the main class which builds up the data structures
// and performs the actual matching.

class RuleMatcher {
public:
	// Argument is tree level on which we build combined regexps
	// (Level 0 is root).
	RuleMatcher(int RE_level = 4);
	~RuleMatcher();

	// Parse the given files and built up data structures.
	bool ReadFiles(const name_list& files);

	// Initialize the matching state for a endpoind of a connection based on
	// the given packet (which should be the first packet encountered for
	// this endpoint). If the matching is triggered by an PIA, a pointer to
	// it needs to be given.
	RuleEndpointState* InitEndpoint(Analyzer* analyzer, const IP_Hdr* ip,
		int caplen, RuleEndpointState* opposite, bool is_orig, PIA* pia);

	// Finish matching for this stream.
	void FinishEndpoint(RuleEndpointState* state);

	// Perform the actual pattern matching on the given data.
	// bol/eol should be set to false for type Rule::PAYLOAD; they're
	// deduced automatically.
	void Match(RuleEndpointState* state, Rule::PatternType type,
			const u_char* data, int data_len,
			bool bol, bool eol, bool clear);

	// Reset the state of the pattern matcher for this endpoint.
	void ClearEndpointState(RuleEndpointState* state);

	void PrintDebug();

	// Interface to parser
	void AddRule(Rule* rule);
	void SetParseError()		{ parse_error = true; }

	// Interface to for getting some statistics
	struct Stats {
		unsigned int matchers;	// # distinct RE matchers

		// # DFA states across all matchers
		unsigned int dfa_states;
		unsigned int computed;	// # computed DFA state transitions
		unsigned int mem;	// #  bytes used by DFA states

		// # cache hits (sampled, multiply by MOVE_TO_FRONT_SAMPLE_SIZE)
		unsigned int hits;
		unsigned int misses;	// # cache misses

		// Average # NFA states per DFA state.
		unsigned int avg_nfa_states;
	};

	Val* BuildRuleStateValue(const Rule* rule,
					const RuleEndpointState* state) const;

	void GetStats(Stats* stats, RuleHdrTest* hdr_test = 0);
	void DumpStats(BroFile* f);

private:
	// Delete node and all children.
	void Delete(RuleHdrTest* node);

	// Build tree containing all added rules.
	void BuildRulesTree();

	// Insert one rule into the current tree.
	void InsertRuleIntoTree(Rule* r, int testnr, RuleHdrTest* dest,
				int level);

	// Traverse tree building the combined regular expressions.
	void BuildRegEx(RuleHdrTest* hdr_test, string_list* exprs, int_list* ids);

	// Build groups of regular epxressions.
	void BuildPatternSets(RuleHdrTest::pattern_set_list* dst,
				const string_list& exprs, const int_list& ids);

	// Check an arbitrary rule if it's satisfied right now.
	// eos signals end of stream
	void ExecRule(Rule* rule, RuleEndpointState* state, bool eos);

	// Evaluate all rules which do not depend on any matched patterns.
	void ExecPureRules(RuleEndpointState* state, bool eos);

	// Eval a rule under the assumption that all its patterns
	// have already matched.  s holds the text the rule matched,
	// or nil if N/A.
	bool ExecRulePurely(Rule* r, BroString* s,
		RuleEndpointState* state, bool eos);

	// Execute the actions associated with a rule.
	void ExecRuleActions(Rule* r, RuleEndpointState* state,
				const u_char* data, int len, bool eos);

	// Evaluate all rule conditions except patterns and "header".
	bool EvalRuleConditions(Rule* r, RuleEndpointState* state,
				const u_char* data, int len, bool eos);

	void PrintTreeDebug(RuleHdrTest* node);

	void DumpStateStats(BroFile* f, RuleHdrTest* hdr_test);

	int RE_level;
	bool parse_error;
	RuleHdrTest* root;
	rule_list rules;
	rule_dict rules_by_id;
};

// Keeps bi-directional matching-state.
class RuleMatcherState {
public:
	RuleMatcherState()	{ orig_match_state = resp_match_state = 0; }
	~RuleMatcherState()
		{ delete orig_match_state; delete resp_match_state; }

	// ip may be nil.
	void InitEndpointMatcher(Analyzer* analyzer, const IP_Hdr* ip,
				int caplen, bool from_orig, PIA* pia = 0);

	// bol/eol should be set to false for type Rule::PAYLOAD; they're
	// deduced automatically.
	void Match(Rule::PatternType type, const u_char* data, int data_len,
			bool from_orig, bool bol, bool eol, bool clear_state);

	void FinishEndpointMatcher();
	void ClearMatchState(bool orig);

	bool MatcherInitialized(bool orig)
		{ return orig ? orig_match_state : resp_match_state; }

private:
	RuleEndpointState* orig_match_state;
	RuleEndpointState* resp_match_state;
};

#endif