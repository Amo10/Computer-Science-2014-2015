"""Sparse rational function fields. """

from __future__ import print_function, division

from operator import add, mul, lt, le, gt, ge

from sympy.core.compatibility import reduce, string_types
from sympy.core.expr import Expr
from sympy.core.symbol import Symbol
from sympy.core.sympify import CantSympify, sympify
from sympy.polys.rings import PolyElement
from sympy.polys.orderings import lex
from sympy.polys.polyerrors import ExactQuotientFailed, CoercionFailed
from sympy.polys.domains.domainelement import DomainElement
from sympy.polys.domains.polynomialring import PolynomialRing
from sympy.polys.domains.fractionfield import FractionField
from sympy.printing.defaults import DefaultPrinting
from sympy.utilities import public
from sympy.utilities.magic import pollute

@public
def field(symbols, domain, order=lex):
    """Construct new rational function field returning (field, x1, ..., xn). """
    _field = FracField(symbols, domain, order)
    return (_field,) + _field.gens

@public
def xfield(symbols, domain, order=lex):
    """Construct new rational function field returning (field, (x1, ..., xn)). """
    _field = FracField(symbols, domain, order)
    return (_field, _field.gens)

@public
def vfield(symbols, domain, order=lex):
    """Construct new rational function field and inject generators into global namespace. """
    _field = FracField(symbols, domain, order)
    pollute([ sym.name for sym in _field.symbols ], _field.gens)
    return _field

@public
def sfield(exprs, *symbols, **options):
    """Construct a field deriving generators and domain from options and input expressions. """
    raise NotImplementedError

_field_cache = {}

class FracField(DefaultPrinting):
    """Multivariate distributed rational function field. """

    def __new__(cls, symbols, domain, order=lex):
        from sympy.polys.rings import PolyRing
        ring = PolyRing(symbols, domain, order)
        symbols = ring.symbols
        ngens = ring.ngens
        domain = ring.domain
        order = ring.order

        _hash = hash((cls.__name__, symbols, ngens, domain, order))
        obj = _field_cache.get(_hash)

        if obj is None:
            obj = object.__new__(cls)
            obj._hash = _hash
            obj.ring = ring
            obj.dtype = type("FracElement", (FracElement,), {"field": obj})
            obj.symbols = symbols
            obj.ngens = ngens
            obj.domain = domain
            obj.order = order

            obj.zero = obj.dtype(ring.zero)
            obj.one = obj.dtype(ring.one)

            obj.gens = obj._gens()

            for symbol, generator in zip(obj.symbols, obj.gens):
                if isinstance(symbol, Symbol):
                    name = symbol.name

                    if not hasattr(obj, name):
                        setattr(obj, name, generator)

            _field_cache[_hash] = obj

        return obj

    def _gens(self):
        """Return a list of polynomial generators. """
        return tuple([ self.dtype(gen) for gen in self.ring.gens ])

    def __getnewargs__(self):
        return (self.symbols, self.domain, self.order)

    def __hash__(self):
        return self._hash

    def __eq__(self, other):
        return self is other

    def __ne__(self, other):
        return self is not other

    def raw_new(self, numer, denom=None):
        return self.dtype(numer, denom)
    def new(self, numer, denom=None):
        if denom is None: denom = self.ring.one
        numer, denom = numer.cancel(denom)
        return self.raw_new(numer, denom)

    def domain_new(self, element):
        return self.domain.convert(element)

    def ground_new(self, element):
        try:
            return self.new(self.ring.ground_new(element))
        except CoercionFailed:
            domain = self.domain

            if not domain.has_Field and domain.has_assoc_Field:
                ring = self.ring
                ground_field = domain.get_field()
                element = ground_field.convert(element)
                numer = ring.ground_new(ground_field.numer(element))
                denom = ring.ground_new(ground_field.denom(element))
                return self.raw_new(numer, denom)
            else:
                raise

    def field_new(self, element):
        if isinstance(element, FracElement):
            if self == element.field:
                return element
            else:
                raise NotImplementedError("conversion")
        elif isinstance(element, PolyElement):
            denom, numer = element.clear_denoms()
            numer = numer.set_ring(self.ring)
            denom = self.ring.ground_new(denom)
            return self.raw_new(numer, denom)
        elif isinstance(element, tuple) and len(element) == 2:
            numer, denom = list(map(self.ring.ring_new, element))
            return self.new(numer, denom)
        elif isinstance(element, string_types):
            raise NotImplementedError("parsing")
        elif isinstance(element, Expr):
            return self.from_expr(element)
        else:
            return self.ground_new(element)

    __call__ = field_new

    def _rebuild_expr(self, expr, mapping):
        domain = self.domain

        def _rebuild(expr):
            generator = mapping.get(expr)

            if generator is not None:
                return generator
            elif expr.is_Add:
                return reduce(add, list(map(_rebuild, expr.args)))
            elif expr.is_Mul:
                return reduce(mul, list(map(_rebuild, expr.args)))
            elif expr.is_Pow and expr.exp.is_Integer:
                return _rebuild(expr.base)**int(expr.exp)
            else:
                try:
                    return domain.convert(expr)
                except CoercionFailed:
                    if not domain.has_Field and domain.has_assoc_Field:
                        return domain.get_field().convert(expr)
                    else:
                        raise

        return _rebuild(sympify(expr))

    def from_expr(self, expr):
        mapping = dict(list(zip(self.symbols, self.gens)))

        try:
            frac = self._rebuild_expr(expr, mapping)
        except CoercionFailed:
            raise ValueError("expected an expression convertible to a rational function in %s, got %s" % (self, expr))
        else:
            return self.field_new(frac)

    def to_domain(self):
        return FractionField(self)

    def to_ring(self):
        from sympy.polys.rings import PolyRing
        return PolyRing(self.symbols, self.domain, self.order)

class FracElement(DomainElement, DefaultPrinting, CantSympify):
    """Element of multivariate distributed rational function field. """

    def __init__(self, numer, denom=None):
        if denom is None:
            denom = self.field.ring.one
        elif not denom:
            raise ZeroDivisionError("zero denominator")

        self.numer = numer
        self.denom = denom

    def raw_new(f, numer, denom):
        return f.__class__(numer, denom)
    def new(f, numer, denom):
        return f.raw_new(*numer.cancel(denom))

    def to_poly(f):
        if f.denom != 1:
            raise ValueError("f.denom should be 1")
        return f.numer

    def parent(self):
        return self.field.to_domain()

    def __getnewargs__(self):
        return (self.field, self.numer, self.denom)

    _hash = None

    def __hash__(self):
        _hash = self._hash
        if _hash is None:
            self._hash = _hash = hash((self.field, self.numer, self.denom))
        return _hash

    def copy(self):
        return self.raw_new(self.numer.copy(), self.denom.copy())

    def set_field(self, new_field):
        if self.field == new_field:
            return self
        else:
            new_ring = new_field.ring
            numer = self.numer.set_ring(new_ring)
            denom = self.denom.set_ring(new_ring)
            return new_field.new(numer, denom)

    def as_expr(self, *symbols):
        return self.numer.as_expr(*symbols)/self.denom.as_expr(*symbols)

    def __eq__(f, g):
        if isinstance(g, f.field.dtype):
            return f.numer == g.numer and f.denom == g.denom
        else:
            return f.numer == g and f.denom == f.field.ring.one

    def __ne__(f, g):
        return not f.__eq__(g)

    def __nonzero__(f):
        return bool(f.numer)

    __bool__ = __nonzero__

    def sort_key(self):
        return (self.denom.sort_key(), self.numer.sort_key())

    def _cmp(f1, f2, op):
        if isinstance(f2, f1.field.dtype):
            return op(f1.sort_key(), f2.sort_key())
        else:
            return NotImplemented

    def __lt__(f1, f2):
        return f1._cmp(f2, lt)
    def __le__(f1, f2):
        return f1._cmp(f2, le)
    def __gt__(f1, f2):
        return f1._cmp(f2, gt)
    def __ge__(f1, f2):
        return f1._cmp(f2, ge)

    def __pos__(f):
        """Negate all coefficients in ``f``. """
        return f.raw_new(f.numer, f.denom)

    def __neg__(f):
        """Negate all coefficients in ``f``. """
        return f.raw_new(-f.numer, f.denom)

    def _extract_ground(self, element):
        domain = self.field.domain

        try:
            element = domain.convert(element)
        except CoercionFailed:
            if not domain.has_Field and domain.has_assoc_Field:
                ground_field = domain.get_field()

                try:
                    element = ground_field.convert(element)
                except CoercionFailed:
                    pass
                else:
                    return -1, ground_field.numer(element), ground_field.denom(element)

            return 0, None, None
        else:
            return 1, element, None

    def __add__(f, g):
        """Add rational functions ``f`` and ``g``. """
        field = f.field

        if not g:
            return f
        elif not f:
            return g
        elif isinstance(g, field.dtype):
            if f.denom == g.denom:
                return f.new(f.numer + g.numer, f.denom)
            else:
                return f.new(f.numer*g.denom + f.denom*g.numer, f.denom*g.denom)
        elif isinstance(g, field.ring.dtype):
            return f.new(f.numer + f.denom*g, f.denom)
        else:
            if isinstance(g, FracElement):
                if isinstance(field.domain, FractionField) and field.domain.field == g.field:
                    pass
                elif isinstance(g.field.domain, FractionField) and g.field.domain.field == field:
                    return g.__radd__(f)
                else:
                    return NotImplemented
            elif isinstance(g, PolyElement):
                if isinstance(field.domain, PolynomialRing) and field.domain.ring == g.ring:
                    pass
                else:
                    return g.__radd__(f)

        return f.__radd__(g)

    def __radd__(f, c):
        if isinstance(c, f.field.ring.dtype):
            return f.new(f.numer + f.denom*c, f.denom)

        op, g_numer, g_denom = f._extract_ground(c)

        if op == 1:
            return f.new(f.numer + f.denom*g_numer, f.denom)
        elif not op:
            return NotImplemented
        else:
            return f.new(f.numer*g_denom + f.denom*g_numer, f.denom*g_denom)

    def __sub__(f, g):
        """Subtract rational functions ``f`` and ``g``. """
        field = f.field

        if not g:
            return f
        elif not f:
            return -g
        elif isinstance(g, field.dtype):
            if f.denom == g.denom:
                return f.new(f.numer - g.numer, f.denom)
            else:
                return f.new(f.numer*g.denom - f.denom*g.numer, f.denom*g.denom)
        elif isinstance(g, field.ring.dtype):
            return f.new(f.numer - f.denom*g, f.denom)
        else:
            if isinstance(g, FracElement):
                if isinstance(field.domain, FractionField) and field.domain.field == g.field:
                    pass
                elif isinstance(g.field.domain, FractionField) and g.field.domain.field == field:
                    return g.__rsub__(f)
                else:
                    return NotImplemented
            elif isinstance(g, PolyElement):
                if isinstance(field.domain, PolynomialRing) and field.domain.ring == g.ring:
                    pass
                else:
                    return g.__rsub__(f)

        op, g_numer, g_denom = f._extract_ground(g)

        if op == 1:
            return f.new(f.numer - f.denom*g_numer, f.denom)
        elif not op:
            return NotImplemented
        else:
            return f.new(f.numer*g_denom - f.denom*g_numer, f.denom*g_denom)

    def __rsub__(f, c):
        if isinstance(c, f.field.ring.dtype):
            return f.new(-f.numer + f.denom*c, f.denom)

        op, g_numer, g_denom = f._extract_ground(c)

        if op == 1:
            return f.new(-f.numer + f.denom*g_numer, f.denom)
        elif not op:
            return NotImplemented
        else:
            return f.new(-f.numer*g_denom + f.denom*g_numer, f.denom*g_denom)

    def __mul__(f, g):
        """Multiply rational functions ``f`` and ``g``. """
        field = f.field

        if not f or not g:
            return field.zero
        elif isinstance(g, field.dtype):
            return f.new(f.numer*g.numer, f.denom*g.denom)
        elif isinstance(g, field.ring.dtype):
            return f.new(f.numer*g, f.denom)
        else:
            if isinstance(g, FracElement):
                if isinstance(field.domain, FractionField) and field.domain.field == g.field:
                    pass
                elif isinstance(g.field.domain, FractionField) and g.field.domain.field == field:
                    return g.__rmul__(f)
                else:
                    return NotImplemented
            elif isinstance(g, PolyElement):
                if isinstance(field.domain, PolynomialRing) and field.domain.ring == g.ring:
                    pass
                else:
                    return g.__rmul__(f)

        return f.__rmul__(g)

    def __rmul__(f, c):
        if isinstance(c, f.field.ring.dtype):
            return f.new(f.numer*c, f.denom)

        op, g_numer, g_denom = f._extract_ground(c)

        if op == 1:
            return f.new(f.numer*g_numer, f.denom)
        elif not op:
            return NotImplemented
        else:
            return f.new(f.numer*g_numer, f.denom*g_denom)

    def __truediv__(f, g):
        """Computes quotient of fractions ``f`` and ``g``. """
        field = f.field

        if not g:
            raise ZeroDivisionError
        elif isinstance(g, field.dtype):
            return f.new(f.numer*g.denom, f.denom*g.numer)
        elif isinstance(g, field.ring.dtype):
            return f.new(f.numer, f.denom*g)
        else:
            if isinstance(g, FracElement):
                if isinstance(field.domain, FractionField) and field.domain.field == g.field:
                    pass
                elif isinstance(g.field.domain, FractionField) and g.field.domain.field == field:
                    return g.__rtruediv__(f)
                else:
                    return NotImplemented
            elif isinstance(g, PolyElement):
                if isinstance(field.domain, PolynomialRing) and field.domain.ring == g.ring:
                    pass
                else:
                    return g.__rtruediv__(f)

        op, g_numer, g_denom = f._extract_ground(g)

        if op == 1:
            return f.new(f.numer, f.denom*g_numer)
        elif not op:
            return NotImplemented
        else:
            return f.new(f.numer*g_denom, f.denom*g_numer)

    __div__ = __truediv__

    def __rtruediv__(f, c):
        if not f:
            raise ZeroDivisionError
        elif isinstance(c, f.field.ring.dtype):
            return f.new(f.denom*c, f.numer)

        op, g_numer, g_denom = f._extract_ground(c)

        if op == 1:
            return f.new(f.denom*g_numer, f.numer)
        elif not op:
            return NotImplemented
        else:
            return f.new(f.denom*g_numer, f.numer*g_denom)

    __rdiv__ = __rtruediv__

    def __pow__(f, n):
        """Raise ``f`` to a non-negative power ``n``. """
        if n >= 0:
            return f.raw_new(f.numer**n, f.denom**n)
        elif not f:
            raise ZeroDivisionError
        else:
            return f.raw_new(f.denom**-n, f.numer**-n)

    def diff(f, x):
        """Computes partial derivative in ``x``.

        Examples
        --------
        >>> from sympy.polys.fields import field
        >>> from sympy.polys.domains import ZZ

        >>> _, x, y, z = field("x,y,z", ZZ)
        >>> ((x**2 + y)/(z + 1)).diff(x)
        2*x/(z + 1)

        """
        x = x.to_poly()
        return f.new(f.numer.diff(x)*f.denom - f.numer*f.denom.diff(x), f.denom**2)

    def __call__(f, *values):
        if 0 < len(values) <= f.field.ngens:
            return f.evaluate(list(zip(f.field.gens, values)))
        else:
            raise ValueError("expected at least 1 and at most %s values, got %s" % (f.field.ngens, len(values)))

    def evaluate(f, x, a=None):
        if isinstance(x, list) and a is None:
            x = [ (X.to_poly(), a) for X, a in x ]
            numer, denom = f.numer.evaluate(x), f.denom.evaluate(x)
        else:
            x = x.to_poly()
            numer, denom = f.numer.evaluate(x, a), f.denom.evaluate(x, a)

        field = numer.ring.to_field()
        return field.new(numer, denom)

    def subs(f, x, a=None):
        if isinstance(x, list) and a is None:
            x = [ (X.to_poly(), a) for X, a in x ]
            numer, denom = f.numer.subs(x), f.denom.subs(x)
        else:
            x = x.to_poly()
            numer, denom = f.numer.subs(x, a), f.denom.subs(x, a)

        return f.new(numer, denom)

    def compose(f, x, a=None):
        raise NotImplementedError
