#include <tree_sitter/parser.h>

#include <cwctype>
#include <string>

#define debug 0
#define print(...) \
  if (debug) printf(__VA_ARGS__)

#define peek() lexer->lookahead

#define next()                       \
  {                                  \
    print("next %s\n", str(peek())); \
    lexer->advance(lexer, false);    \
  }

#define skip()                       \
  {                                  \
    print("skip %s\n", str(peek())); \
    lexer->advance(lexer, true);     \
  }

#define stop()                       \
  {                                  \
    print("stop %s\n", str(peek())); \
    lexer->mark_end(lexer);          \
  }

#define set(symbol)                        \
  {                                        \
    print("set %s\n", TokenTypes[symbol]); \
    lexer->result_symbol = symbol;         \
  }

namespace {

using std::string;

enum TokenType {
  HEREDOC_START,
  HEREDOC_BODY,
  HEREDOC_END,
};

const char *TokenTypes[] = {"HEREDOC_START", "HEREDOC_BODY", "HEREDOC_END"};

static const char *str(int32_t chr) {
  switch (chr) {
    case '\n':
      return "\\n";
    case '\r':
      return "\\r";
    case '\t':
      return "\\t";
    case ' ':
      return "\\s";
    case '\0':
      return "\\0";
    default:
      if (iswspace(chr)) {
        return "\\s";
      }

      string str;
      str += chr;
      return str.c_str();
  }
}

struct Scanner {
  unsigned serialize(char *buffer) {
    if (delimiter.length() + 2 >= TREE_SITTER_SERIALIZATION_BUFFER_SIZE) return 0;
    buffer[0] = is_nowdoc;
    buffer[1] = did_start;
    buffer[2] = did_body;
    delimiter.copy(&buffer[3], delimiter.length());
    return delimiter.length() + 3;
  }

  void deserialize(const char *buffer, unsigned length) {
    if (length == 0) {
      is_nowdoc = false;
      did_start = false;
      did_body = false;
      delimiter.clear();
    } else {
      is_nowdoc = buffer[0];
      did_start = buffer[1];
      did_body = buffer[2];
      delimiter.assign(&buffer[3], &buffer[length]);
    }
  }

  bool scan(TSLexer *lexer, const bool *expected) {
    print("\n> ");
    if (expected[HEREDOC_END]) print("%s ", TokenTypes[HEREDOC_END]);
    if (expected[HEREDOC_BODY]) print("%s ", TokenTypes[HEREDOC_BODY]);
    if (expected[HEREDOC_START]) print("%s ", TokenTypes[HEREDOC_START]);
    print("\n");

    print("peek %s\n", str(peek()));

    if ((expected[HEREDOC_BODY] || expected[HEREDOC_END])) {
      if (delimiter.empty()) return false;

      if (!did_start) {
        if (peek() == '\n') {
          did_start = true;
          skip();
        } else {
          return false;
        }
      }

      if (did_body && peek() == '\n') {
        skip();
      }

      if (expected[HEREDOC_END] && scan_end(lexer, true)) {
        delimiter.clear();
        is_nowdoc = false;
        did_body = false;

        set(HEREDOC_END);
        return true;
      }

      if (expected[HEREDOC_BODY] && scan_body(lexer)) {
        set(HEREDOC_BODY);
        return true;
      }

      // If HEREDOC_BODY or HEREDOC_END is expected, then HEREDOC_START is
      // not valid even if expected.
    } else if (expected[HEREDOC_START]) {
      if (scan_start(lexer)) {
        set(HEREDOC_START);
        return true;
      }
    }

    return false;
  }

  bool scan_start(TSLexer *lexer) {
    print("scan start\n");

    while (iswspace(peek())) skip();

    int32_t quote = 0;

    if (peek() == '\'' || peek() == '"') {
      quote = peek();
      is_nowdoc = true;
      next();
    } else {
      is_nowdoc = false;
    }

    delimiter.clear();

    if (iswalpha(peek()) || peek() == '_') {
      delimiter += peek();
      next();

      while (iswalnum(peek()) || peek() == '_') {
        delimiter += peek();
        next();
      }
    }

    print("del %s\n", delimiter.c_str());

    if (is_nowdoc) {
      if (peek() == quote) {
        next();
      } else {
        return false;
      }
    }

    if (peek() != '\n') {
      delimiter.clear();
    }

    return !delimiter.empty();
  }

  /**
   * Scan for matching heredoc end. If mark_end is true, then we're trying to match the heredoc
   * end token. Otherwise, we're only looking ahead to know if we found the heredoc body end.
   */
  bool scan_end(TSLexer *lexer, bool mark_end) {
    print("scan end\n");

    if (mark_end && peek() == '\n') {
      did_start = true;
      // If mark_end is true, stop() should not have been called so it's safe to skip().
      skip();
    }

    for (int i = 0; i < delimiter.length(); ++i) {
      if (delimiter[i] == peek()) {
        next();
      } else {
        print("scan end ->\n");
        return false;
      }
    }

    if (mark_end) {
      stop();
    }

    // In all cases, stop() should have already been called, so ; is never included in the token.
    if (peek() == ';') {
      next();
    }

    print("scan end ->\n");
    return peek() == '\n';
  }

  bool scan_body(TSLexer *lexer) {
    print("scan body\n");

    if (!is_nowdoc) {
      if (peek() == '{') next();
      if (peek() == '$') {
        next();
        if (is_identifier_start_char(peek())) {
          return false;
        }
      }
    }

    for (;;) {
      switch (peek()) {
        case '\0': {
          return false;
        }

        case '\\': {
          next();
          next();
          break;
        }

        case '{': {
          if (is_nowdoc) {
            next();
          } else {
            stop();
            next();

            if (peek() == '$') {
              return true;
            }
          }

          break;
        }

        case '$': {
          if (is_nowdoc) {
            next();
          } else {
            stop();
            next();

            if (is_identifier_start_char(peek())) {
              return true;
            }
          }
          break;
        }

        case '\n': {
          if (did_start) {
            stop();
            next();

            if (scan_end(lexer, false)) {
              did_body = true;
              return true;
            }
          } else {
            skip();
            stop();
            did_start = true;

            if (scan_end(lexer, false)) {
              did_body = true;
              return false;
            }
          }
          break;
        }

        default: {
          next();
          break;
        }
      }
    }
  }

  // This function returns true if c is a valid starting character of a name/identifier
  bool is_identifier_start_char(int32_t c) {
    return (c == '_') || ('a' <= c && c <= 'z') || ('A' <= c && c <= 'Z') || (128 <= c && c <= 255);
  }

  string delimiter;
  bool is_nowdoc;
  bool did_body;
  bool did_start;
};

}  // namespace

extern "C" {

void *tree_sitter_hack_external_scanner_create() { return new Scanner(); }

bool tree_sitter_hack_external_scanner_scan(void *payload, TSLexer *lexer, const bool *expected) {
  Scanner *scanner = static_cast<Scanner *>(payload);
  return scanner->scan(lexer, expected);
}

unsigned tree_sitter_hack_external_scanner_serialize(void *payload, char *state) {
  Scanner *scanner = static_cast<Scanner *>(payload);
  return scanner->serialize(state);
}

void tree_sitter_hack_external_scanner_deserialize(
    void *payload, const char *state, unsigned length) {
  Scanner *scanner = static_cast<Scanner *>(payload);
  scanner->deserialize(state, length);
}

void tree_sitter_hack_external_scanner_destroy(void *payload) {
  Scanner *scanner = static_cast<Scanner *>(payload);
  delete scanner;
}
}
