import numpy
import pytest
from bota.anomaly import SimpleExpSmoothing, Welford


def test_welford():
    vals = numpy.random.randint(100, size=(1000))

    w = Welford()

    for x in vals:
        w.update(x)

    assert numpy.allclose(w.mean, numpy.mean(vals))
    assert numpy.allclose(w.var, numpy.var(vals))
    assert numpy.allclose(w.std, numpy.std(vals))


def test_exponential_smoothing():
    for alpha in numpy.linspace(0, 1, 20):
        ses = SimpleExpSmoothing(alpha)

        ses.update(1)

        assert ses.pred == 1
        assert ses.std_e == 0

        ses.update(1)
        ses.update(1)

        assert ses.pred == 1
        assert ses.std_e == 0

        ses.update(100)

        pred = (
            alpha * 100
            + alpha * (1 - alpha) * 1
            + alpha * (1 - alpha) ** 2 * 1
            + (1 - alpha) ** 3 * 1
        )

        std_e = numpy.std([0, 0, 99])

        assert numpy.allclose(pred, ses.pred)
        assert numpy.allclose(std_e, ses.std_e)


def test_invalid():
    with pytest.raises(ValueError) as e:
        SimpleExpSmoothing(-0.1)

    assert e.type == ValueError

    with pytest.raises(ValueError) as e:
        SimpleExpSmoothing(1.1)

    assert e.type == ValueError
