from sympy.physics.mechanics import (dynamicsymbols, ReferenceFrame, Point,
                                    RigidBody, LagrangesMethod, Particle,
                                    kinetic_energy, dynamicsymbols, inertia,
                                    potential_energy, Lagrangian)
from sympy import symbols, pi, sin, cos, tan, simplify, expand, Function, \
    Derivative


def test_disc_on_an_incline_plane():
    # Disc rolling on an inclined plane
    # First the generalized coordinates are created. The mass center of the
    # disc is located from top vertex of the inclined plane by the generalized
    # coordinate 'y'. The orientation of the disc is defined by the angle
    # 'theta'. The mass of the disc is 'm' and its radius is 'R'. The length of
    # the inclined path is 'l', the angle of inclination is 'alpha'. 'g' is the
    # gravitational constant.
    y, theta = dynamicsymbols('y theta')
    yd, thetad = dynamicsymbols('y theta', 1)
    m, g, R, l, alpha = symbols('m g R l alpha')

    # Next, we create the inertial reference frame 'N'. A reference frame 'A'
    # is attached to the inclined plane. Finally a frame is created which is attached to the disk.
    N = ReferenceFrame('N')
    A = N.orientnew('A', 'Axis', [pi/2 - alpha, N.z])
    B = A.orientnew('B', 'Axis', [-theta, A.z])

    # Creating the disc 'D'; we create the point that represents the mass
    # center of the disc and set its velocity. The inertia dyadic of the disc
    # is created. Finally, we create the disc.
    Do = Point('Do')
    Do.set_vel(N, yd * A.x)
    I = m * R**2 / 2 * B.z | B.z
    D = RigidBody('D', Do, B, m, (I, Do))

    # To construct the Lagrangian, 'L', of the disc, we determine its kinetic
    # and potential energies, T and U, respectively. L is defined as the
    # difference between T and U.
    D.set_potential_energy(m * g * (l - y) * sin(alpha))
    L = Lagrangian(N, D)

    # We then create the list of generalized coordinates and constraint
    # equations. The constraint arises due to the disc rolling without slip on
    # on the inclined path. Also, the constraint is holonomic but we supply the
    # differentiated holonomic equation as the 'LagrangesMethod' class requires
    # that. We then invoke the 'LagrangesMethod' class and supply it the
    # necessary arguments and generate the equations of motion. The'rhs' method
    # solves for the q_double_dots (i.e. the second derivative with respect to
    # time  of the generalized coordinates and the lagrange multiplers.
    q = [y, theta]
    coneq = [yd - R * thetad]
    m = LagrangesMethod(L, q, coneq)
    m.form_lagranges_equations()
    assert m.rhs()[2] == 2*g*sin(alpha)/3


def test_simp_pen():
    # This tests that the equations generated by LagrangesMethod are identical
    # to those obtained by hand calculations. The system under consideration is
    # the simple pendulum.
    # We begin by creating the generalized coordinates as per the requirements
    # of LagrangesMethod. Also we created the associate symbols
    # that characterize the system: 'm' is the mass of the bob, l is the length
    # of the massless rigid rod connecting the bob to a point O fixed in the
    # inertial frame.
    q, u = dynamicsymbols('q u')
    qd, ud = dynamicsymbols('q u ', 1)
    l, m, g = symbols('l m g')

    # We then create the inertial frame and a frame attached to the massless
    # string following which we define the inertial angular velocity of the
    # string.
    N = ReferenceFrame('N')
    A = N.orientnew('A', 'Axis', [q, N.z])
    A.set_ang_vel(N, qd * N.z)

    # Next, we create the point O and fix it in the inertial frame. We then
    # locate the point P to which the bob is attached. Its corresponding
    # velocity is then determined by the 'two point formula'.
    O = Point('O')
    O.set_vel(N, 0)
    P = O.locatenew('P', l * A.x)
    P.v2pt_theory(O, N, A)

    # The 'Particle' which represents the bob is then created and its
    # Lagrangian generated.
    Pa = Particle('Pa', P, m)
    Pa.set_potential_energy(- m * g * l * cos(q))
    L = Lagrangian(N, Pa)

    # The 'LagrangesMethod' class is invoked to obtain equations of motion.
    lm = LagrangesMethod(L, [q])
    lm.form_lagranges_equations()
    RHS = lm.rhs()
    assert RHS[1] == -g*sin(q)/l


def test_dub_pen():

    # The system considered is the double pendulum. Like in the
    # test of the simple pendulum above, we begin by creating the generalized
    # coordinates and the simple generalized speeds and accelerations which
    # will be used later. Following this we create frames and points necessary
    # for the kinematics. The procedure isn't explicitly explained as this is
    # similar to the simple  pendulum. Also this is documented on the pydy.org
    # website.
    q1, q2 = dynamicsymbols('q1 q2')
    q1d, q2d = dynamicsymbols('q1 q2', 1)
    q1dd, q2dd = dynamicsymbols('q1 q2', 2)
    u1, u2 = dynamicsymbols('u1 u2')
    u1d, u2d = dynamicsymbols('u1 u2', 1)
    l, m, g = symbols('l m g')

    N = ReferenceFrame('N')
    A = N.orientnew('A', 'Axis', [q1, N.z])
    B = N.orientnew('B', 'Axis', [q2, N.z])

    A.set_ang_vel(N, q1d * A.z)
    B.set_ang_vel(N, q2d * A.z)

    O = Point('O')
    P = O.locatenew('P', l * A.x)
    R = P.locatenew('R', l * B.x)

    O.set_vel(N, 0)
    P.v2pt_theory(O, N, A)
    R.v2pt_theory(P, N, B)

    ParP = Particle('ParP', P, m)
    ParR = Particle('ParR', R, m)

    ParP.set_potential_energy(- m * g * l * cos(q1))
    ParR.set_potential_energy(- m * g * l * cos(q1) - m * g * l * cos(q2))
    L = Lagrangian(N, ParP, ParR)
    lm = LagrangesMethod(L, [q1, q2])
    lm.form_lagranges_equations()

    assert simplify(l*m*(2*g*sin(q1) + l*sin(q1)*sin(q2)*q2dd
        + l*sin(q1)*cos(q2)*q2d**2 - l*sin(q2)*cos(q1)*q2d**2
        + l*cos(q1)*cos(q2)*q2dd + 2*l*q1dd) - lm.eom[0]) == 0
    assert simplify(l*m*(g*sin(q2) + l*sin(q1)*sin(q2)*q1dd
        - l*sin(q1)*cos(q2)*q1d**2 + l*sin(q2)*cos(q1)*q1d**2
        + l*cos(q1)*cos(q2)*q1dd + l*q2dd) - lm.eom[1]) == 0


def test_rolling_disc():
    # Rolling Disc Example
    # Here the rolling disc is formed from the contact point up, removing the
    # need to introduce generalized speeds. Only 3 configuration and 3
    # speed variables are need to describe this system, along with the
    # disc's mass and radius, and the local gravity.
    q1, q2, q3 = dynamicsymbols('q1 q2 q3')
    q1d, q2d, q3d = dynamicsymbols('q1 q2 q3', 1)
    r, m, g = symbols('r m g')

    # The kinematics are formed by a series of simple rotations. Each simple
    # rotation creates a new frame, and the next rotation is defined by the new
    # frame's basis vectors. This example uses a 3-1-2 series of rotations, or
    # Z, X, Y series of rotations. Angular velocity for this is defined using
    # the second frame's basis (the lean frame).
    N = ReferenceFrame('N')
    Y = N.orientnew('Y', 'Axis', [q1, N.z])
    L = Y.orientnew('L', 'Axis', [q2, Y.x])
    R = L.orientnew('R', 'Axis', [q3, L.y])

    # This is the translational kinematics. We create a point with no velocity
    # in N; this is the contact point between the disc and ground. Next we form
    # the position vector from the contact point to the disc's center of mass.
    # Finally we form the velocity and acceleration of the disc.
    C = Point('C')
    C.set_vel(N, 0)
    Dmc = C.locatenew('Dmc', r * L.z)
    Dmc.v2pt_theory(C, N, R)

    # Forming the inertia dyadic.
    I = inertia(L, m / 4 * r**2, m / 2 * r**2, m / 4 * r**2)
    BodyD = RigidBody('BodyD', Dmc, R, m, (I, Dmc))

    # Finally we form the equations of motion, using the same steps we did
    # before. Supply the Lagrangian, the generalized speeds.
    BodyD.set_potential_energy(- m * g * r * cos(q2))
    Lag = Lagrangian(N, BodyD)
    q = [q1, q2, q3]
    q1 = Function('q1')
    q2 = Function('q2')
    q3 = Function('q3')
    l = LagrangesMethod(Lag, q)
    l.form_lagranges_equations()
    RHS = l.rhs()
    RHS.simplify()
    t = symbols('t')

    assert (l.mass_matrix[3:6] == [0, 5*m*r**2/4, 0])
    assert RHS[4].simplify() == (
        (-8*g*sin(q2(t)) + r*(5*sin(2*q2(t))*Derivative(q1(t), t) +
        12*cos(q2(t))*Derivative(q3(t), t))*Derivative(q1(t), t))/(10*r))
    assert RHS[5] == (-5*cos(q2(t))*Derivative(q1(t), t) + 6*tan(q2(t)
        )*Derivative(q3(t), t) + 4*Derivative(q1(t), t)/cos(q2(t))
        )*Derivative(q2(t), t)
