import {
  getHighlighterExpressionsFromQuery,
  getNormalizedLokiQuery,
  isLogsQuery,
  isQueryWithParser,
  isValidQuery,
} from './query_utils';
import { LokiQuery, LokiQueryType } from './types';

describe('getHighlighterExpressionsFromQuery', () => {
  it('returns no expressions for empty query', () => {
    expect(getHighlighterExpressionsFromQuery('')).toEqual([]);
  });

  it('returns an expression for query with filter using quotes', () => {
    expect(getHighlighterExpressionsFromQuery('{foo="bar"} |= "x"')).toEqual(['x']);
  });

  it('returns an expression for query with filter using backticks', () => {
    expect(getHighlighterExpressionsFromQuery('{foo="bar"} |= `x`')).toEqual(['x']);
  });

  it('returns expressions for query with filter chain', () => {
    expect(getHighlighterExpressionsFromQuery('{foo="bar"} |= "x" |~ "y"')).toEqual(['x', 'y']);
  });

  it('returns expressions for query with filter chain using both backticks and quotes', () => {
    expect(getHighlighterExpressionsFromQuery('{foo="bar"} |= "x" |~ `y`')).toEqual(['x', 'y']);
  });

  it('returns expression for query with log parser', () => {
    expect(getHighlighterExpressionsFromQuery('{foo="bar"} |= "x" | logfmt')).toEqual(['x']);
  });

  it('returns expressions for query with filter chain followed by log parser', () => {
    expect(getHighlighterExpressionsFromQuery('{foo="bar"} |= "x" |~ "y" | logfmt')).toEqual(['x', 'y']);
  });

  it('returns drops expressions for query with negative filter chain using quotes', () => {
    expect(getHighlighterExpressionsFromQuery('{foo="bar"} |= "x" != "y"')).toEqual(['x']);
  });

  it('returns expressions for query with filter chain using backticks', () => {
    expect(getHighlighterExpressionsFromQuery('{foo="bar"} |= `x` |~ `y`')).toEqual(['x', 'y']);
  });

  it('returns expressions for query with filter chain using quotes and backticks', () => {
    expect(getHighlighterExpressionsFromQuery('{foo="bar"} |= "x" |~ `y`')).toEqual(['x', 'y']);
  });

  it('returns null if filter term is not wrapped in double quotes', () => {
    expect(getHighlighterExpressionsFromQuery('{foo="bar"} |= x')).toEqual([]);
  });

  it('escapes filter term if regex filter operator is not used', () => {
    expect(getHighlighterExpressionsFromQuery('{foo="bar"} |= "x[yz].w"')).toEqual(['x\\[yz\\]\\.w']);
  });

  it('does not escape filter term if regex filter operator is used', () => {
    expect(getHighlighterExpressionsFromQuery('{foo="bar"} |~ "x[yz].w" |~ "z.+"')).toEqual(['x[yz].w', 'z.+']);
  });

  it('removes extra backslash escaping if regex filter operator and quotes are used', () => {
    expect(getHighlighterExpressionsFromQuery('{foo="bar"} |~ "\\\\w+"')).toEqual(['\\w+']);
  });

  it('does not remove backslash escaping if regex filter operator and backticks are used', () => {
    expect(getHighlighterExpressionsFromQuery('{foo="bar"} |~ `\\w+`')).toEqual(['\\w+']);
  });
});

describe('getNormalizedLokiQuery', () => {
  function expectNormalized(inputProps: Object, outputQueryType: LokiQueryType) {
    const input: LokiQuery = { refId: 'A', expr: 'test1', ...inputProps };
    const output = getNormalizedLokiQuery(input);
    expect(output).toStrictEqual({ refId: 'A', expr: 'test1', queryType: outputQueryType });
  }

  it('handles no props case', () => {
    expectNormalized({}, LokiQueryType.Range);
  });

  it('handles old-style instant case', () => {
    expectNormalized({ instant: true, range: false }, LokiQueryType.Instant);
  });

  it('handles old-style range case', () => {
    expectNormalized({ instant: false, range: true }, LokiQueryType.Range);
  });

  it('handles new+old style instant', () => {
    expectNormalized({ instant: true, range: false, queryType: LokiQueryType.Range }, LokiQueryType.Range);
  });

  it('handles new+old style range', () => {
    expectNormalized({ instant: false, range: true, queryType: LokiQueryType.Instant }, LokiQueryType.Instant);
  });

  it('handles new<>old conflict (new wins), range', () => {
    expectNormalized({ instant: false, range: true, queryType: LokiQueryType.Range }, LokiQueryType.Range);
  });

  it('handles new<>old conflict (new wins), instant', () => {
    expectNormalized({ instant: true, range: false, queryType: LokiQueryType.Instant }, LokiQueryType.Instant);
  });

  it('handles invalid new, range', () => {
    expectNormalized({ queryType: 'invalid' }, LokiQueryType.Range);
  });

  it('handles invalid new, when old-range exists, use old', () => {
    expectNormalized({ instant: false, range: true, queryType: 'invalid' }, LokiQueryType.Range);
  });

  it('handles invalid new, when old-instant exists, use old', () => {
    expectNormalized({ instant: true, range: false, queryType: 'invalid' }, LokiQueryType.Instant);
  });
});

describe('isValidQuery', () => {
  it('returns false if invalid query', () => {
    expect(isValidQuery('{job="grafana')).toBe(false);
  });
  it('returns true if valid query', () => {
    expect(isValidQuery('{job="grafana"}')).toBe(true);
  });
});

describe('isLogsQuery', () => {
  it('returns false if metrics query', () => {
    expect(isLogsQuery('rate({job="grafana"}[5m])')).toBe(false);
  });
  it('returns true if valid query', () => {
    expect(isLogsQuery('{job="grafana"}')).toBe(true);
  });
});

describe('isQueryWithParser', () => {
  it('returns false if query without parser', () => {
    expect(isQueryWithParser('rate({job="grafana" |= "error" }[5m])')).toBe(false);
  });
  it('returns true if log query with parser', () => {
    expect(isQueryWithParser('{job="grafana"} | json')).toBe(true);
  });

  it('returns true if metric query with parser', () => {
    expect(isQueryWithParser('rate({job="grafana"} | json [5m])')).toBe(true);
  });
});
