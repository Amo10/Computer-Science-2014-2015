from sympy.solvers import solve
from sympy import Symbol
x = Symbol('x')
#output = solve([90827228398801655999039668844188632466596513329046552288953024163839612298599929910164697793546539641557945308022387813414800213987212533489914397519583435906900600253870069270402587564481558413622491158899329135822821923624875888267392912625378899755812703090090124576608402157059305482681016909811379356694 == pow((37*y + (37**2)), 3, 177780248325474334668138287007170352387973746192089328834399405375885752736671708284357561998269321055182067684739770138435887061808854468861043343117512028236772541072841560871052386088606831360514784078441923997401417092864271432957609051331371486017913542108160719526188742876089596588752592461291748855889), 13542325634081372757767838888520934251575235836777871632523232963311960335312965801456068653114149782951624174617202860973776211238814248741785676940312224978778853876525985836906572171156535731861167730524317976141306734084939700282182537335367488605879007932980737730211910239672570972132722343559820988446 == pow((52*y + (52**2)), 3, 177780248325474334668138287007170352387973746192089328834399405375885752736671708284357561998269321055182067684739770138435887061808854468861043343117512028236772541072841560871052386088606831360514784078441923997401417092864271432957609051331371486017913542108160719526188742876089596588752592461291748855889)],y)
output = solve((90827228398801655999039668844188632466596513329046552288953024163839612298599929910164697793546539641557945308022387813414800213987212533489914397519583435906900600253870069270402587564481558413622491158899329135822821923624875888267392912625378899755812703090090124576608402157059305482681016909811379356694 == 50653*(x + 37)**3,
13542325634081372757767838888520934251575235836777871632523232963311960335312965801456068653114149782951624174617202860973776211238814248741785676940312224978778853876525985836906572171156535731861167730524317976141306734084939700282182537335367488605879007932980737730211910239672570972132722343559820988446 == 140608*(x + 52)**3),x)

print(output)

