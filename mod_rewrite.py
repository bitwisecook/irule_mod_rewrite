#!/usr/bin/env python3

# mod_rewrite to iRule converter v0.0.4
# 2018/Jul/24
# James Deucker <me@bitwisecook.org>

import sys
from collections import defaultdict, namedtuple
import argparse

CookieFlag = namedtuple(
    "CookieFlag", ("name", "value", "domain", "lifetime", "path", "secure", "httponly")
)


class RewriteCond:
    pass


class RewriteRule:
    @staticmethod
    def _parse_flags(rawflags):
        flags = {
            "backrefesc": False,
            "backrefnoplus": False,
            "chain": False,
            "cookie": False,
            "discardpath": False,
            "end": False,
            "env": False,
            "forbidden": False,
            "gone": False,
            "handler": False,
            "last": False,
            "next": False,
            "nocase": False,
            "noescape": False,
            "nosubreq": False,
            "proxy": False,
            "passthrough": False,
            "qsappend": False,
            "qsdiscard": False,
            "qslast": False,
            "redirect": False,
            "skip": False,
            "type": False,
        }
        for ff in rawflags:
            # here we just loop through the list of flags setting up the dictionary with the data
            x = ff.split("=", maxsplit=1)
            # split the flag into the flag name and if present, value
            f = x[0].lower()
            v = x[1] if len(x) == 2 else None
            if f == "b":
                flags["backrefesc"] = True
                raise NotImplementedError(
                    f"flag backrefesc is not supported in rule {rule}"
                )
            elif f in ("backrefnoplus", "bnp"):
                flags["backrefnoplus"] = True
                raise NotImplementedError(
                    f"flag backrefnoplus is not supported in rule {rule}"
                )
            elif f in ("chain", "c"):
                flags["chain"] = True
                raise NotImplementedError(f"flag chain is not supported in rule {rule}")
            elif f in ("cookie", "co"):
                vv = v.split(";") if ";" in v else v.split(":")
                for _ in range(7 - len(vv)):
                    vv.append(None)
                flags["cookie"] = CookieFlag(*vv)
            elif f in ("discardpath", "dpi"):
                flags["discardpath"] = True
                raise NotImplementedError(
                    f"flag discardpath is not supported in rule {rule}"
                )
            elif f == "end":
                flags["end"] = True
            elif f in ("env", "e"):
                if f[1] == "!":
                    flags["env"] = (True, *(v[1:].split(":")))
                else:
                    flags["env"] = (False, *(v.split(":")))
                raise NotImplementedError(f"flag env is not supported in rule {rule}")
            elif f in ("forbidden", "f"):
                flags["forbidden"] = True
                flags["last"] = True if self.enable_opt else False
                self.substitution = "-"
            elif f in ("gone", "g"):
                flags["gone"] = True
                flags["last"] = True if self.enable_opt else False
                self.substitution = "-"
            elif f in ("handler", "h"):
                flags["handler"] = v
                raise NotImplementedError(
                    f"flag handler is not supported in rule {rule}"
                )
            elif f in ("last", "l"):
                flags["last"] = True
            elif f in ("next", "n"):
                flags["next"] = True
                print(f"NEXT: {rule}")
            elif f in ("nocase", "nc"):
                flags["nocase"] = True
            elif f in ("noescape", "ne"):
                flags["noescape"] = True
                raise NotImplementedError(
                    f"flag noescape is not supported in rule {rule}"
                )
            elif f in ("nosubreq", "ns"):
                flags["nosubreq"] = True
                raise NotImplementedError(
                    f"flag nosubreq is not supported in rule {rule}"
                )
            elif f in ("proxy", "p"):
                flags["proxy"] = True
                raise NotImplementedError(f"flag proxy is not supported in rule {rule}")
            elif f in ("passthrough", "pt"):
                flags["passthrough"] = True
                raise NotImplementedError(
                    f"flag passthrough is not supported in rule {rule}"
                )
            elif f in ("qsappend", "qsa"):
                if flags["qsdiscard"]:
                    raise SyntaxError(
                        f"Attempt to both qsappend and qsdiscard in rule {rule}"
                    )
                flags["qsappend"] = True
            elif f in ("qsdiscard", "qsd"):
                if flags["qsappend"]:
                    raise SyntaxError(
                        f"Attempt to both qsappend and qsdiscard in rule {rule}"
                    )
                flags["qsdiscard"] = True
            elif f in ("qslast", "qsl"):
                flags["qslast"] = True
                raise NotImplementedError(
                    f"flag qslast is not supported in rule {rule}"
                )
            elif f in ("redirect", "r"):
                flags["redirect"] = (
                    v.replace("temp", "302")
                    .replace("permanent", "301")
                    .replace("seeother", "303")
                    or "302"
                )
            elif f in ("skip", "s"):
                flags["skip"] = v
                raise NotImplementedError(f"flag skip is not supported in rule {rule}")
            elif f in ("type", "t"):
                flags["type"] = v
        if flags["redirect"] and not flags["last"]:
            raise SyntaxError(
                f"flag redirect without flag last are not supported in rule {rule}"
            )
        if flags["redirect"] and flags["type"]:
            raise SyntaxError(
                f"flag redirect with flag type are not supported in rule {rule}"
            )
        return flags

    def __init__(self, rule: str, enable_opt: bool = True):
        self.enable_opt = enable_opt
        self.rule = rule
        # split the line into the rule parts
        r = rule.strip().split(" ")
        self.pattern = r[1].strip('"')
        # a tiny bit of optimisation of the pattern here
        # we snip off a useless ^.* or .*$ as they're meaningless
        # and let the rule optimisation find exact/startswith/endswith
        if self.pattern[:3] == "^.*":
            self.pattern = self.pattern[3:]
        if self.pattern[-3:] == ".*$":
            self.pattern = self.pattern[:-3]
        if self.pattern[:2] == ".*":
            self.pattern = self.pattern[2:]
        if self.pattern[-2:] == ".*":
            self.pattern = self.pattern[:-2]
        # we need to translate the regex to Tcl
        # this obviously won't cover all the corner cases
        self.substitution = (
            r[2]
            .strip('"')
            .replace("\\", "\\\\")
            .replace("$", "\\")
            .replace("{", "\\{")
            .replace("}", "\\}")
        )
        self._flags = r[3].strip("[]").split(",") if len(r) == 4 else []
        self.flags = self._parse_flags(self._flags)

        if self.substitution.endswith("&%\\{QUERY_STRING\\}"):
            # functionally QSA is the same as having &%{QUERY_STRING} on the end
            self.flags["qsappend"] = True
            self.substitution = self.substitution[:-18]

    def __repr__(self):
        return f'RewriteRule {self.pattern} {self.substitution if self.substitution else ""} {self._flags if self._flags else ""}'


def indent(tab, text):
    ret = ""
    for l in text.splitlines():
        ret += (" " * (tab * 4)) + l + "\n"
    return ret


class LTMRule:
    @staticmethod
    def format(rule):
        ret = ""
        tab = 0
        for line in rule.splitlines():
            line = line.strip()

            if line.endswith("{"):
                if line.startswith("}"):
                    # cases like '\} else \{'
                    tab -= 1
                ret += " " * (tab * 4) + line + "\n"
                tab += 1
            elif line.startswith("}"):
                tab -= 1
                ret += " " * (tab * 4) + line + "\n"
            else:
                ret += " " * (tab * 4) + line + "\n"

        return ret.rstrip()

    def __init__(self, rules, enable_opt: bool = True):
        self.enable_opt = enable_opt
        self.rules = [LTMRuleRegSub(_, self) for _ in rules]
        if any(_.uses_qsappend for _ in self.rules):
            self.uri_builder = '[expr {$keep_query?[expr {$uri contains "?"?"$uri&$qs_orig":"$uri?$qs_orig"}]:""}]'
        else:
            self.uri_builder = "$uri"

    def __str__(self):
        ret = "when HTTP_REQUEST priority 500 {\n"
        ret += "set keep_query 1\n"
        ret += "set uri [HTTP::uri]\n"
        ret += "set qs_orig [HTTP::query]\n"
        if any(_.uses_next for _ in self.rules):
            ret += "set next 1\n"
            ret += "while $next {\n"
            ret += "set next 0\n"
        for s in self.rules:
            ret += f"{s}\n".replace("%\\{QUERY_STRING\\}", "$qs_orig").replace(
                "%\\{HOST\\}", "[HTTP::host]"
            )
        if any(_.uses_next for _ in self.rules):
            ret += "}\n"
        ret += f"HTTP::uri {self.uri_builder}\n"
        ret += "}\n"
        ret += "\n"
        if any(_.uses_mime_type for _ in self.rules):
            ret += "when HTTP_RESPONSE priority 500 {\n"
            ret += "if {[info exists mime_type]} {\n"
            ret += "HTTP::header replace Content-Type $mime_type\n"
            ret += "unset -nocomplain mime_type\n"
            ret += "}\n"
            ret += "}\n"
        return self.format(ret)


class LTMRuleRegSub:
    def __init__(self, rule: RewriteRule, irule: LTMRule):
        self.rule = rule
        self.flags = rule.flags
        self.irule = irule

    def __str__(self):
        cmd = False
        ret = "-nocase " if self.flags["nocase"] else ""
        ret += "{%s} " % self.rule.pattern
        ret += "$uri"
        if self.rule.enable_opt and self.is_pattern_exact and self.flags["last"]:
            ret = f'$uri eq "{self.rule.pattern[1:-1]}"'
        elif self.rule.enable_opt and self.is_pattern_startswith and self.flags["last"]:
            ret = f'$uri starts_with "{self.rule.pattern[1:]}"'
        elif self.rule.enable_opt and self.is_pattern_endswith and self.flags["last"]:
            ret = f'$uri ends_with "{self.rule.pattern[:-1]}"'
        elif self.rule.enable_opt and self.is_pattern_contains and self.flags["last"]:
            ret = f'$uri contains "{self.rule.pattern}"'
        elif self.requires_sub:
            cmd = True
            ret = "regsub " + ret
            ret += ' "%s' % self.rule.substitution
            ret += '" uri'
        else:
            cmd = True
            ret = "regexp " + ret
        if self.requires_if:
            if cmd:
                ret = "[" + ret + "]"
            ret = "if {" + ret + "} {\n"
            if self.flags["qsdiscard"]:
                ret += "set keep_query 0\n"
            if self.flags["qsappend"]:
                ret += 'append uri "&${qs_orig}"\n'
            if self.flags["type"]:
                ret += f'set mime_type "{self.flags["type"]}"\n'
            if self.flags["cookie"]:
                ret += f'HTTP::cookie insert name "{self.flags["cookie"].name}" value "{self.flags["cookie"].value}"'
                if self.flags["cookie"].path:
                    ret += f' path "{self.flags["cookie"].path}"'
                if self.flags["cookie"].domain:
                    ret += f' domain "{self.flags["cookie"].domain.strip(".")}"'
                ret += "\n"
                if self.flags["cookie"].secure:
                    ret += f'HTTP::cookie secure "{self.flags["cookie"].name}" enable\n'
                if self.flags["cookie"].httponly:
                    ret += (
                        f'HTTP::cookie httponly "{self.flags["cookie"].name}" enable\n'
                    )
                if self.flags["cookie"].lifetime:
                    ret += f'HTTP::cookie expires "{self.flags["cookie"].name}" {self.flags["cookie"].lifetime} relative\n'

            if self.flags["redirect"]:
                ret += f'HTTP::redirect {self.flags["redirect"]} {self.irule.uri_builder}\n'
                ret += "return\n"
            elif self.flags["gone"]:
                ret += f'HTTP::respond 401 content "Gone" noserver\n'
                ret += "return\n"
            elif self.flags["last"]:
                ret += f"HTTP::uri {self.irule.uri_builder}\n"
                ret += "return\n"
            elif self.flags["next"]:
                ret += "set next 1\n"
                ret += "continue\n"
            elif self.flags["end"]:
                ret += "return\n"
            ret += "}"
        return ret

    @property
    def uses_mime_type(self):
        return self.flags["type"]

    @property
    def uses_next(self):
        return self.flags["next"]

    @property
    def uses_qsappend(self):
        return self.flags["qsappend"]

    @property
    def uses_flags(self):
        return any(_ != False for _ in self.flags.values())

    @property
    def requrires_regex(self):
        # an absolutely terrible way to figure out if we need to use a regex at all
        return not (
            self.is_pattern_exact
            or self.is_pattern_startswith
            or self.is_pattern_endswith
        )

    @property
    def requires_sub(self):
        return self.requrires_regex and self.rule.substitution != "-"

    @property
    def requires_if(self):
        return (
            self.flags["last"]
            or self.flags["qsdiscard"]
            or self.flags["qsappend"]
            or self.flags["cookie"]
            or self.flags["type"]
        )

    @property
    def is_pattern_exact(self):
        # this will miss all sorts of corner cases
        return (
            self.rule.pattern[0] == "^"
            and self.rule.pattern[-1] == "$"
            and not uses_regex_symbols(self.rule.pattern[1:-1])
        )

    @property
    def is_pattern_startswith(self):
        # this will miss all sorts of corner cases
        return (
            self.rule.pattern[0] == "^"
            and self.rule.pattern[-1] != "$"
            and not uses_regex_symbols(self.rule.pattern[1:])
        )

    @property
    def is_pattern_endswith(self):
        # this will miss all sorts of corner cases
        return (
            self.rule.pattern[0] != "^"
            and self.rule.pattern[-1] == "$"
            and not uses_regex_symbols(self.rule.pattern[:-1])
        )

    @property
    def is_pattern_contains(self):
        # this will miss all sorts of corner cases
        return (
            self.rule.pattern[0] != "^"
            and self.rule.pattern[-1] != "$"
            and not uses_regex_symbols(self.rule.pattern)
        )


def uses_regex_symbols(regex):
    return any(
        _
        in regex.replace("\\\\", "XXXX")
        .replace("\\$", "XX")
        .replace("\\*", "XX")
        .replace("\\+", "XX")
        .replace("\\?", "XX")
        .replace("\\[", "XX")
        .replace("\\]", "XX")
        .replace("\\{", "XX")
        .replace("\\}", "XX")
        .replace("\\(", "XX")
        .replace("\\)", "XX")
        .replace("\\?", "XX")
        for _ in (".", "*", "+", "?", "[", "]", "{", "}", "(", ")")
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Process a mod_rewrite ruleset into an iRule"
    )
    parser.add_argument(
        "--enable-opt",
        dest="enable_opt",
        action="store_true",
        help="Enable simple optimisation transforms",
    )
    parser.add_argument(
        "--disable-opt",
        dest="enable_opt",
        action="store_false",
        help="Disable simple optimisation transforms",
    )
    parser.add_argument(
        "-i",
        "--input",
        type=argparse.FileType("r"),
        default=sys.stdin,
        help='Input file of mod_rewrite rules, "-" or unspecified will use stdin',
    )
    parser.add_argument(
        "-o",
        "--output",
        type=argparse.FileType("w"),
        default=sys.stdout,
        help='Output file of iRule Tcl code, "-" or unspecified will use stdout',
    )
    parser.set_defaults(enable_opt=True)
    args = parser.parse_args()

    p_rules = []
    for rule in args.input:
        if rule.startswith("RewriteRule"):
            p_rules.append(RewriteRule(rule, enable_opt=args.enable_opt))

    r = LTMRule(p_rules)

    print(r, file=args.output)
