from __future__ import print_function, division

from sympy.core import Add, S, C, sympify, oo, pi, Dummy, Rational
from sympy.core.function import Function, ArgumentIndexError
from sympy.core.compatibility import xrange
from .zeta_functions import zeta
from .error_functions import erf
from sympy.functions.elementary.exponential import log
from sympy.functions.elementary.integers import floor
from sympy.functions.elementary.miscellaneous import sqrt
from sympy.functions.elementary.trigonometric import csc
from sympy.functions.combinatorial.numbers import bernoulli
from sympy.functions.combinatorial.factorials import rf
from sympy.functions.combinatorial.numbers import harmonic


###############################################################################
############################ COMPLETE GAMMA FUNCTION ##########################
###############################################################################

class gamma(Function):
    r"""
    The gamma function

    .. math::
        \Gamma(x) := \int^{\infty}_{0} t^{x-1} e^{t} \mathrm{d}t.

    The ``gamma`` function implements the function which passes through the
    values of the factorial function, i.e. `\Gamma(n) = (n - 1)!` when n is
    an integer. More general, `\Gamma(z)` is defined in the whole complex
    plane except at the negative integers where there are simple poles.

    Examples
    ========

    >>> from sympy import S, I, pi, oo, gamma
    >>> from sympy.abc import x

    Several special values are known:

    >>> gamma(1)
    1
    >>> gamma(4)
    6
    >>> gamma(S(3)/2)
    sqrt(pi)/2

    The Gamma function obeys the mirror symmetry:

    >>> from sympy import conjugate
    >>> conjugate(gamma(x))
    gamma(conjugate(x))

    Differentiation with respect to x is supported:

    >>> from sympy import diff
    >>> diff(gamma(x), x)
    gamma(x)*polygamma(0, x)

    Series expansion is also supported:

    >>> from sympy import series
    >>> series(gamma(x), x, 0, 3)
    1/x - EulerGamma + x*(EulerGamma**2/2 + pi**2/12) + x**2*(-EulerGamma*pi**2/12 + polygamma(2, 1)/6 - EulerGamma**3/6) + O(x**3)

    We can numerically evaluate the gamma function to arbitrary precision
    on the whole complex plane:

    >>> gamma(pi).evalf(40)
    2.288037795340032417959588909060233922890
    >>> gamma(1+I).evalf(20)
    0.49801566811835604271 - 0.15494982830181068512*I

    See Also
    ========

    lowergamma: Lower incomplete gamma function.
    uppergamma: Upper incomplete gamma function.
    polygamma: Polygamma function.
    loggamma: Log Gamma function.
    digamma: Digamma function.
    trigamma: Trigamma function.
    beta: Euler Beta function.

    References
    ==========

    .. [1] http://en.wikipedia.org/wiki/Gamma_function
    .. [2] http://dlmf.nist.gov/5
    .. [3] http://mathworld.wolfram.com/GammaFunction.html
    .. [4] http://functions.wolfram.com/GammaBetaErf/Gamma/
    """

    unbranched = True

    def fdiff(self, argindex=1):
        if argindex == 1:
            return gamma(self.args[0])*polygamma(0, self.args[0])
        else:
            raise ArgumentIndexError(self, argindex)

    @classmethod
    def eval(cls, arg):
        if arg.is_Number:
            if arg is S.NaN:
                return S.NaN
            elif arg is S.Infinity:
                return S.Infinity
            elif arg.is_Integer:
                if arg.is_positive:
                    return C.factorial(arg - 1)
                else:
                    return S.ComplexInfinity
            elif arg.is_Rational:
                if arg.q == 2:
                    n = abs(arg.p) // arg.q

                    if arg.is_positive:
                        k, coeff = n, S.One
                    else:
                        n = k = n + 1

                        if n & 1 == 0:
                            coeff = S.One
                        else:
                            coeff = S.NegativeOne

                    for i in range(3, 2*k, 2):
                        coeff *= i

                    if arg.is_positive:
                        return coeff*sqrt(S.Pi) / 2**n
                    else:
                        return 2**n*sqrt(S.Pi) / coeff

    def _eval_expand_func(self, **hints):
        arg = self.args[0]
        if arg.is_Rational:
            if abs(arg.p) > arg.q:
                x = Dummy('x')
                n = arg.p // arg.q
                p = arg.p - n*arg.q
                return gamma(x + n)._eval_expand_func().subs(x, Rational(p, arg.q))

        if arg.is_Add:
            coeff, tail = arg.as_coeff_add()
            if coeff and coeff.q != 1:
                intpart = floor(coeff)
                tail = (coeff - intpart,) + tail
                coeff = intpart
            tail = arg._new_rawargs(*tail, reeval=False)
            return gamma(tail)*C.RisingFactorial(tail, coeff)

        return self.func(*self.args)

    def _eval_conjugate(self):
        return self.func(self.args[0].conjugate())

    def _eval_is_real(self):
        return self.args[0].is_real

    def _eval_rewrite_as_tractable(self, z):
        return C.exp(loggamma(z))

    def _eval_nseries(self, x, n, logx):
        x0 = self.args[0].limit(x, 0)
        if not (x0.is_Integer and x0 <= 0):
            return super(gamma, self)._eval_nseries(x, n, logx)
        t = self.args[0] - x0
        return (gamma(t + 1)/rf(self.args[0], -x0 + 1))._eval_nseries(x, n, logx)

    def _latex(self, printer, exp=None):
        if len(self.args) != 1:
            raise ValueError("Args length should be 1")
        aa = printer._print(self.args[0])
        if exp:
            return r'\Gamma^{%s}{\left(%s \right)}' % (printer._print(exp), aa)
        else:
            return r'\Gamma{\left(%s \right)}' % aa

    @staticmethod
    def _latex_no_arg(printer):
        return r'\Gamma'


###############################################################################
################## LOWER and UPPER INCOMPLETE GAMMA FUNCTIONS #################
###############################################################################

class lowergamma(Function):
    r"""
    The lower incomplete gamma function.

    It can be defined as the meromorphic continuation of

    .. math::
        \gamma(s, x) := \int_0^x t^{s-1} e^{-t} \mathrm{d}t = \Gamma(s) - \Gamma(s, x).

    This can be shown to be the same as

    .. math::
        \gamma(s, x) = \frac{x^s}{s} {}_1F_1\left({s \atop s+1} \middle| -x\right),

    where :math:`{}_1F_1` is the (confluent) hypergeometric function.

    Examples
    ========

    >>> from sympy import lowergamma, S
    >>> from sympy.abc import s, x
    >>> lowergamma(s, x)
    lowergamma(s, x)
    >>> lowergamma(3, x)
    -x**2*exp(-x) - 2*x*exp(-x) + 2 - 2*exp(-x)
    >>> lowergamma(-S(1)/2, x)
    -2*sqrt(pi)*erf(sqrt(x)) - 2*exp(-x)/sqrt(x)

    See Also
    ========

    gamma: Gamma function.
    uppergamma: Upper incomplete gamma function.
    polygamma: Polygamma function.
    loggamma: Log Gamma function.
    digamma: Digamma function.
    trigamma: Trigamma function.
    beta: Euler Beta function.

    References
    ==========

    .. [1] http://en.wikipedia.org/wiki/Incomplete_gamma_function#Lower_Incomplete_Gamma_Function
    .. [2] Abramowitz, Milton; Stegun, Irene A., eds. (1965), Chapter 6, Section 5,
           Handbook of Mathematical Functions with Formulas, Graphs, and Mathematical Tables
    .. [3] http://dlmf.nist.gov/8
    .. [4] http://functions.wolfram.com/GammaBetaErf/Gamma2/
    .. [5] http://functions.wolfram.com/GammaBetaErf/Gamma3/
    """


    def fdiff(self, argindex=2):
        from sympy import meijerg, unpolarify
        if argindex == 2:
            a, z = self.args
            return C.exp(-unpolarify(z))*z**(a - 1)
        elif argindex == 1:
            a, z = self.args
            return gamma(a)*digamma(a) - log(z)*uppergamma(a, z) \
                - meijerg([], [1, 1], [0, 0, a], [], z)

        else:
            raise ArgumentIndexError(self, argindex)

    @classmethod
    def eval(cls, a, x):
        # For lack of a better place, we use this one to extract branching
        # information. The following can be
        # found in the literature (c/f references given above), albeit scattered:
        # 1) For fixed x != 0, lowergamma(s, x) is an entire function of s
        # 2) For fixed positive integers s, lowergamma(s, x) is an entire
        #    function of x.
        # 3) For fixed non-positive integers s,
        #    lowergamma(s, exp(I*2*pi*n)*x) =
        #              2*pi*I*n*(-1)**(-s)/factorial(-s) + lowergamma(s, x)
        #    (this follows from lowergamma(s, x).diff(x) = x**(s-1)*exp(-x)).
        # 4) For fixed non-integral s,
        #    lowergamma(s, x) = x**s*gamma(s)*lowergamma_unbranched(s, x),
        #    where lowergamma_unbranched(s, x) is an entire function (in fact
        #    of both s and x), i.e.
        #    lowergamma(s, exp(2*I*pi*n)*x) = exp(2*pi*I*n*a)*lowergamma(a, x)
        from sympy import unpolarify, I, factorial, exp
        nx, n = x.extract_branch_factor()
        if a.is_integer and a.is_positive:
            nx = unpolarify(x)
            if nx != x:
                return lowergamma(a, nx)
        elif a.is_integer and a.is_nonpositive:
            if n != 0:
                return 2*pi*I*n*(-1)**(-a)/factorial(-a) + lowergamma(a, nx)
        elif n != 0:
            return exp(2*pi*I*n*a)*lowergamma(a, nx)

        # Special values.
        if a.is_Number:
            # TODO this should be non-recursive
            if a is S.One:
                return S.One - C.exp(-x)
            elif a is S.Half:
                return sqrt(pi)*erf(sqrt(x))
            elif a.is_Integer or (2*a).is_Integer:
                b = a - 1
                if b.is_positive:
                    return b*cls(b, x) - x**b * C.exp(-x)

                if not a.is_Integer:
                    return (cls(a + 1, x) + x**a * C.exp(-x))/a

    def _eval_evalf(self, prec):
        from sympy.mpmath import mp
        from sympy import Expr
        a = self.args[0]._to_mpmath(prec)
        z = self.args[1]._to_mpmath(prec)
        oprec = mp.prec
        mp.prec = prec
        res = mp.gammainc(a, 0, z)
        mp.prec = oprec
        return Expr._from_mpmath(res, prec)

    def _eval_conjugate(self):
        z = self.args[1]
        if not z in (S.Zero, S.NegativeInfinity):
            return self.func(self.args[0].conjugate(), z.conjugate())

    def _eval_rewrite_as_uppergamma(self, s, x):
        return gamma(s) - uppergamma(s, x)

    def _eval_rewrite_as_expint(self, s, x):
        from sympy import expint
        if s.is_integer and s.is_nonpositive:
            return self
        return self.rewrite(uppergamma).rewrite(expint)

    @staticmethod
    def _latex_no_arg(printer):
        return r'\gamma'

class uppergamma(Function):
    r"""
    The upper incomplete gamma function.

    It can be defined as the meromorphic continuation of

    .. math::
        \Gamma(s, x) := \int_x^\infty t^{s-1} e^{-t} \mathrm{d}t = \Gamma(s) - \gamma(s, x).

    where `\gamma(s, x)` is the lower incomplete gamma function,
    :class:`lowergamma`. This can be shown to be the same as

    .. math::
        \Gamma(s, x) = \Gamma(s) - \frac{x^s}{s} {}_1F_1\left({s \atop s+1} \middle| -x\right),

    where :math:`{}_1F_1` is the (confluent) hypergeometric function.

    The upper incomplete gamma function is also essentially equivalent to the
    generalized exponential integral:

    .. math::
        \operatorname{E}_{n}(x) = \int_{1}^{\infty}{\frac{e^{-xt}}{t^n} \, dt} = x^{n-1}\Gamma(1-n,x).

    Examples
    ========

    >>> from sympy import uppergamma, S
    >>> from sympy.abc import s, x
    >>> uppergamma(s, x)
    uppergamma(s, x)
    >>> uppergamma(3, x)
    x**2*exp(-x) + 2*x*exp(-x) + 2*exp(-x)
    >>> uppergamma(-S(1)/2, x)
    -2*sqrt(pi)*(-erf(sqrt(x)) + 1) + 2*exp(-x)/sqrt(x)
    >>> uppergamma(-2, x)
    expint(3, x)/x**2

    See Also
    ========

    gamma: Gamma function.
    lowergamma: Lower incomplete gamma function.
    polygamma: Polygamma function.
    loggamma: Log Gamma function.
    digamma: Digamma function.
    trigamma: Trigamma function.
    beta: Euler Beta function.

    References
    ==========

    .. [1] http://en.wikipedia.org/wiki/Incomplete_gamma_function#Upper_Incomplete_Gamma_Function
    .. [2] Abramowitz, Milton; Stegun, Irene A., eds. (1965), Chapter 6, Section 5,
           Handbook of Mathematical Functions with Formulas, Graphs, and Mathematical Tables
    .. [3] http://dlmf.nist.gov/8
    .. [4] http://functions.wolfram.com/GammaBetaErf/Gamma2/
    .. [5] http://functions.wolfram.com/GammaBetaErf/Gamma3/
    .. [6] http://en.wikipedia.org/wiki/Exponential_integral#Relation_with_other_functions
    """


    def fdiff(self, argindex=2):
        from sympy import meijerg, unpolarify
        if argindex == 2:
            a, z = self.args
            return -C.exp(-unpolarify(z))*z**(a - 1)
        elif argindex == 1:
            a, z = self.args
            return uppergamma(a, z)*log(z) + meijerg([], [1, 1], [0, 0, a], [], z)
        else:
            raise ArgumentIndexError(self, argindex)

    def _eval_evalf(self, prec):
        from sympy.mpmath import mp
        from sympy import Expr
        a = self.args[0]._to_mpmath(prec)
        z = self.args[1]._to_mpmath(prec)
        oprec = mp.prec
        mp.prec = prec
        res = mp.gammainc(a, z, mp.inf)
        mp.prec = oprec
        return Expr._from_mpmath(res, prec)

    @classmethod
    def eval(cls, a, z):
        from sympy import unpolarify, I, factorial, exp, expint
        if z.is_Number:
            if z is S.NaN:
                return S.NaN
            elif z is S.Infinity:
                return S.Zero
            elif z is S.Zero:
                # TODO: Holds only for Re(a) > 0:
                return gamma(a)

        # We extract branching information here. C/f lowergamma.
        nx, n = z.extract_branch_factor()
        if a.is_integer and (a > 0) is True:
            nx = unpolarify(z)
            if z != nx:
                return uppergamma(a, nx)
        elif a.is_integer and (a <= 0) is True:
            if n != 0:
                return -2*pi*I*n*(-1)**(-a)/factorial(-a) + uppergamma(a, nx)
        elif n != 0:
            return gamma(a)*(1 - exp(2*pi*I*n*a)) + exp(2*pi*I*n*a)*uppergamma(a, nx)

        # Special values.
        if a.is_Number:
            # TODO this should be non-recursive
            if a is S.One:
                return C.exp(-z)
            elif a is S.Half:
                return sqrt(pi)*(1 - erf(sqrt(z)))  # TODO could use erfc...
            elif a.is_Integer or (2*a).is_Integer:
                b = a - 1
                if b.is_positive:
                    return b*cls(b, z) + z**b * C.exp(-z)
                elif b.is_Integer:
                    return expint(-b, z)*unpolarify(z)**(b + 1)

                if not a.is_Integer:
                    return (cls(a + 1, z) - z**a * C.exp(-z))/a

    def _eval_conjugate(self):
        z = self.args[1]
        if not z in (S.Zero, S.NegativeInfinity):
            return self.func(self.args[0].conjugate(), z.conjugate())

    def _eval_rewrite_as_lowergamma(self, s, x):
        return gamma(s) - lowergamma(s, x)

    def _eval_rewrite_as_expint(self, s, x):
        from sympy import expint
        return expint(1 - s, x)*x**s


###############################################################################
###################### POLYGAMMA and LOGGAMMA FUNCTIONS #######################
###############################################################################

class polygamma(Function):
    r"""
    The function ``polygamma(n, z)`` returns ``log(gamma(z)).diff(n + 1)``.

    It is a meromorphic function on `\mathbb{C}` and defined as the (n+1)-th
    derivative of the logarithm of the gamma function:

    .. math::
        \psi^{(n)} (z) := \frac{\mathrm{d}^{n+1}}{\mathrm{d} z^{n+1}} \log\Gamma(z).

    Examples
    ========

    Several special values are known:

    >>> from sympy import S, polygamma
    >>> polygamma(0, 1)
    -EulerGamma
    >>> polygamma(0, 1/S(2))
    -2*log(2) - EulerGamma
    >>> polygamma(0, 1/S(3))
    -3*log(3)/2 - sqrt(3)*pi/6 - EulerGamma
    >>> polygamma(0, 1/S(4))
    -3*log(2) - pi/2 - EulerGamma
    >>> polygamma(0, 2)
    -EulerGamma + 1
    >>> polygamma(0, 23)
    -EulerGamma + 19093197/5173168

    >>> from sympy import oo, I
    >>> polygamma(0, oo)
    oo
    >>> polygamma(0, -oo)
    oo
    >>> polygamma(0, I*oo)
    oo
    >>> polygamma(0, -I*oo)
    oo

    Differentiation with respect to x is supported:

    >>> from sympy import Symbol, diff
    >>> x = Symbol("x")
    >>> diff(polygamma(0, x), x)
    polygamma(1, x)
    >>> diff(polygamma(0, x), x, 2)
    polygamma(2, x)
    >>> diff(polygamma(0, x), x, 3)
    polygamma(3, x)
    >>> diff(polygamma(1, x), x)
    polygamma(2, x)
    >>> diff(polygamma(1, x), x, 2)
    polygamma(3, x)
    >>> diff(polygamma(2, x), x)
    polygamma(3, x)
    >>> diff(polygamma(2, x), x, 2)
    polygamma(4, x)

    >>> n = Symbol("n")
    >>> diff(polygamma(n, x), x)
    polygamma(n + 1, x)
    >>> diff(polygamma(n, x), x, 2)
    polygamma(n + 2, x)

    We can rewrite polygamma functions in terms of harmonic numbers:

    >>> from sympy import harmonic
    >>> polygamma(0, x).rewrite(harmonic)
    harmonic(x - 1) - EulerGamma
    >>> polygamma(2, x).rewrite(harmonic)
    2*harmonic(x - 1, 3) - 2*zeta(3)
    >>> ni = Symbol("n", integer=True)
    >>> polygamma(ni, x).rewrite(harmonic)
    (-1)**(n + 1)*(-harmonic(x - 1, n + 1) + zeta(n + 1))*factorial(n)

    See Also
    ========

    gamma: Gamma function.
    lowergamma: Lower incomplete gamma function.
    uppergamma: Upper incomplete gamma function.
    loggamma: Log Gamma function.
    digamma: Digamma function.
    trigamma: Trigamma function.
    beta: Euler Beta function.

    References
    ==========

    .. [1] http://en.wikipedia.org/wiki/Polygamma_function
    .. [2] http://mathworld.wolfram.com/PolygammaFunction.html
    .. [3] http://functions.wolfram.com/GammaBetaErf/PolyGamma/
    .. [4] http://functions.wolfram.com/GammaBetaErf/PolyGamma2/
    """


    def fdiff(self, argindex=2):
        if argindex == 2:
            n, z = self.args[:2]
            return polygamma(n + 1, z)
        else:
            raise ArgumentIndexError(self, argindex)

    def _eval_is_positive(self):
        if self.args[1].is_positive and (self.args[0] > 0) is True:
            return self.args[0].is_odd

    def _eval_is_negative(self):
        if self.args[1].is_positive and (self.args[0] > 0) is True:
            return self.args[0].is_even

    def _eval_is_real(self):
        return self.args[0].is_real

    def _eval_aseries(self, n, args0, x, logx):
        if args0[1] != oo or not \
                (self.args[0].is_Integer and self.args[0].is_nonnegative):
            return super(polygamma, self)._eval_aseries(n, args0, x, logx)
        z = self.args[1]
        N = self.args[0]

        if N == 0:
            # digamma function series
            # Abramowitz & Stegun, p. 259, 6.3.18
            r = log(z) - 1/(2*z)
            o = None
            if n < 2:
                o = C.Order(1/z, x)
            else:
                m = C.ceiling((n + 1)//2)
                l = [bernoulli(2*k) / (2*k*z**(2*k)) for k in range(1, m)]
                r -= Add(*l)
                o = C.Order(1/z**(2*m), x)
            return r._eval_nseries(x, n, logx) + o
        else:
            # proper polygamma function
            # Abramowitz & Stegun, p. 260, 6.4.10
            # We return terms to order higher than O(x**n) on purpose
            # -- otherwise we would not be able to return any terms for
            #    quite a long time!
            fac = gamma(N)
            e0 = fac + N*fac/(2*z)
            m = C.ceiling((n + 1)//2)
            for k in range(1, m):
                fac = fac*(2*k + N - 1)*(2*k + N - 2) / ((2*k)*(2*k - 1))
                e0 += bernoulli(2*k)*fac/z**(2*k)
            o = C.Order(1/z**(2*m), x)
            if n == 0:
                o = C.Order(1/z, x)
            elif n == 1:
                o = C.Order(1/z**2, x)
            r = e0._eval_nseries(z, n, logx) + o
            return -1 * (-1/z)**N * r

    @classmethod
    def eval(cls, n, z):
        n, z = list(map(sympify, (n, z)))
        from sympy import unpolarify

        if n.is_integer:
            if n.is_nonnegative:
                nz = unpolarify(z)
                if z != nz:
                    return polygamma(n, nz)

            if n == -1:
                return loggamma(z)
            else:
                if z.is_Number:
                    if z is S.NaN:
                        return S.NaN
                    elif z is S.Infinity:
                        if n.is_Number:
                            if n is S.Zero:
                                return S.Infinity
                            else:
                                return S.Zero
                    elif z.is_Integer:
                        if z.is_nonpositive:
                            return S.ComplexInfinity
                        else:
                            if n is S.Zero:
                                return -S.EulerGamma + C.harmonic(z - 1, 1)
                            elif n.is_odd:
                                return (-1)**(n + 1)*C.factorial(n)*zeta(n + 1, z)

        if n == 0:
            if z is S.NaN:
                return S.NaN
            elif z.is_Rational:
                # TODO actually *any* n/m can be done, but that is messy
                lookup = {S(1)/2: -2*log(2) - S.EulerGamma,
                          S(1)/3: -S.Pi/2/sqrt(3) - 3*log(3)/2 - S.EulerGamma,
                          S(1)/4: -S.Pi/2 - 3*log(2) - S.EulerGamma,
                          S(3)/4: -3*log(2) - S.EulerGamma + S.Pi/2,
                          S(2)/3: -3*log(3)/2 + S.Pi/2/sqrt(3) - S.EulerGamma}
                if z > 0:
                    n = floor(z)
                    z0 = z - n
                    if z0 in lookup:
                        return lookup[z0] + Add(*[1/(z0 + k) for k in range(n)])
                elif z < 0:
                    n = floor(1 - z)
                    z0 = z + n
                    if z0 in lookup:
                        return lookup[z0] - Add(*[1/(z0 - 1 - k) for k in range(n)])
            elif z in (S.Infinity, S.NegativeInfinity):
                return S.Infinity
            else:
                t = z.extract_multiplicatively(S.ImaginaryUnit)
                if t in (S.Infinity, S.NegativeInfinity):
                    return S.Infinity

        # TODO n == 1 also can do some rational z

    def _eval_expand_func(self, **hints):
        n, z = self.args

        if n.is_Integer and n.is_nonnegative:
            if z.is_Add:
                coeff = z.args[0]
                if coeff.is_Integer:
                    e = -(n + 1)
                    if coeff > 0:
                        tail = Add(*[C.Pow(
                            z - i, e) for i in xrange(1, int(coeff) + 1)])
                    else:
                        tail = -Add(*[C.Pow(
                            z + i, e) for i in xrange(0, int(-coeff))])
                    return polygamma(n, z - coeff) + (-1)**n*C.factorial(n)*tail

            elif z.is_Mul:
                coeff, z = z.as_two_terms()
                if coeff.is_Integer and coeff.is_positive:
                    tail = [ polygamma(n, z + C.Rational(
                        i, coeff)) for i in xrange(0, int(coeff)) ]
                    if n == 0:
                        return Add(*tail)/coeff + log(coeff)
                    else:
                        return Add(*tail)/coeff**(n + 1)
                z *= coeff

        return polygamma(n, z)

    def _eval_rewrite_as_zeta(self, n, z):
        if n >= S.One:
            return (-1)**(n + 1)*C.factorial(n)*zeta(n + 1, z)
        else:
            return self

    def _eval_rewrite_as_harmonic(self, n, z):
        if n.is_integer:
            if n == S.Zero:
                return harmonic(z - 1) - S.EulerGamma
            else:
                return S.NegativeOne**(n+1) * C.factorial(n) * (C.zeta(n+1) - harmonic(z-1, n+1))

    def _eval_as_leading_term(self, x):
        n, z = [a.as_leading_term(x) for a in self.args]
        o = C.Order(z, x)
        if n == 0 and o.contains(1/x):
            return o.getn() * log(x)
        else:
            return self.func(n, z)


class loggamma(Function):
    r"""
    The ``loggamma`` function implements the logarithm of the
    gamma function i.e, `\log\Gamma(x)`.

    Examples
    ========

    >>> from sympy import S, I, pi, oo, loggamma
    >>> from sympy.abc import x

    The loggamma function obeys the mirror symmetry
    if `x \in \mathbb{C} \setminus \{-\infty, 0\}`:

    >>> from sympy import conjugate
    >>> conjugate(loggamma(x))
    loggamma(conjugate(x))
    >>> conjugate(loggamma(-oo))
    conjugate(loggamma(-oo))

    Differentiation with respect to x is supported:

    >>> from sympy import diff
    >>> diff(loggamma(x), x)
    polygamma(0, x)

    Series expansion is also supported:

    >>> from sympy import series
    >>> series(loggamma(x), x, 0, 4)
    -log(x) - EulerGamma*x + pi**2*x**2/12 + x**3*polygamma(2, 1)/6 + O(x**4)

    We can numerically evaluate the gamma function to arbitrary precision
    on the whole complex plane:

    >>> loggamma(5).evalf(30)
    3.17805383034794561964694160130
    >>> loggamma(I).evalf(20)
    -0.65092319930185633889 - 1.8724366472624298171*I

    See Also
    ========

    gamma: Gamma function.
    lowergamma: Lower incomplete gamma function.
    uppergamma: Upper incomplete gamma function.
    polygamma: Polygamma function.
    digamma: Digamma function.
    trigamma: Trigamma function.
    beta: Euler Beta function.

    References
    ==========

    .. [1] http://en.wikipedia.org/wiki/Gamma_function
    .. [2] http://dlmf.nist.gov/5
    .. [3] http://mathworld.wolfram.com/LogGammaFunction.html
    .. [4] http://functions.wolfram.com/GammaBetaErf/LogGamma/
    """

    nargs = 1  # there is no eval defined so we must define this

    # TODO: Implement various special known values

    def _eval_nseries(self, x, n, logx=None):
        x0 = self.args[0].limit(x, 0)
        if x0 is S.Zero:
            f = self._eval_rewrite_as_intractable(*self.args)
            return f._eval_nseries(x, n, logx)
        return super(loggamma, self)._eval_nseries(x, n, logx)

    def _eval_aseries(self, n, args0, x, logx):
        if args0[0] != oo:
            return super(loggamma, self)._eval_aseries(n, args0, x, logx)
        z = self.args[0]
        m = min(n, C.ceiling((n + S(1))/2))
        r = log(z)*(z - S(1)/2) - z + log(2*pi)/2
        l = [bernoulli(2*k) / (2*k*(2*k - 1)*z**(2*k - 1)) for k in range(1, m)]
        o = None
        if m == 0:
            o = C.Order(1, x)
        else:
            o = C.Order(1/z**(2*m - 1), x)
        # It is very inefficient to first add the order and then do the nseries
        return (r + Add(*l))._eval_nseries(x, n, logx) + o

    def _eval_rewrite_as_intractable(self, z):
        return log(gamma(z))

    def _eval_is_real(self):
        return self.args[0].is_real

    def _eval_conjugate(self):
        z = self.args[0]
        if not z in (S.Zero, S.NegativeInfinity):
            return self.func(z.conjugate())

    def fdiff(self, argindex=1):
        if argindex == 1:
            return polygamma(0, self.args[0])
        else:
            raise ArgumentIndexError(self, argindex)


def digamma(x):
    r"""
    The digamma function is the first derivative of the loggamma function i.e,

    .. math::
        \psi(x) := \frac{\mathrm{d}}{\mathrm{d} z} \log\Gamma(z)
                = \frac{\Gamma'(z)}{\Gamma(z) }

    In this case, ``digamma(z) = polygamma(0, z)``.

    See Also
    ========

    gamma: Gamma function.
    lowergamma: Lower incomplete gamma function.
    uppergamma: Upper incomplete gamma function.
    polygamma: Polygamma function.
    loggamma: Log Gamma function.
    trigamma: Trigamma function.
    beta: Euler Beta function.

    References
    ==========

    .. [1] http://en.wikipedia.org/wiki/Digamma_function
    .. [2] http://mathworld.wolfram.com/DigammaFunction.html
    .. [3] http://functions.wolfram.com/GammaBetaErf/PolyGamma2/
    """
    return polygamma(0, x)


def trigamma(x):
    r"""
    The trigamma function is the second derivative of the loggamma function i.e,

    .. math::
        \psi^{(1)}(z) := \frac{\mathrm{d}^{2}}{\mathrm{d} z^{2}} \log\Gamma(z).

    In this case, ``trigamma(z) = polygamma(1, z)``.

    See Also
    ========

    gamma: Gamma function.
    lowergamma: Lower incomplete gamma function.
    uppergamma: Upper incomplete gamma function.
    polygamma: Polygamma function.
    loggamma: Log Gamma function.
    digamma: Digamma function.
    beta: Euler Beta function.

    References
    ==========

    .. [1] http://en.wikipedia.org/wiki/Trigamma_function
    .. [2] http://mathworld.wolfram.com/TrigammaFunction.html
    .. [3] http://functions.wolfram.com/GammaBetaErf/PolyGamma2/
    """
    return polygamma(1, x)


###############################################################################
############################### BETA FUNCTIONS ################################
###############################################################################

def beta(x, y):
    r"""
    Euler Beta function:

    .. math::
        \mathrm{B}(x, y) := \frac{\Gamma(x) \Gamma(y)}{\Gamma(x+y)}

    See Also
    ========

    gamma: Gamma function.
    lowergamma: Lower incomplete gamma function.
    uppergamma: Upper incomplete gamma function.
    polygamma: Polygamma function.
    loggamma: Log Gamma function.
    digamma: Digamma function.
    trigamma: Trigamma function.

    References
    ==========

    .. [1] https://en.wikipedia.org/wiki/Beta_function
    .. [2] http://dlmf.nist.gov/5.12
    .. [3] http://mathworld.wolfram.com/BetaFunction.html
    .. [4] http://functions.wolfram.com/GammaBetaErf/Beta/
    """
    return gamma(x)*gamma(y) / gamma(x + y)
