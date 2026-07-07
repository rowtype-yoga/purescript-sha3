<?php

// Data.Function.Uncurried — complete phpurs FFI.
//
// An FnN value is a PHP closure taking N positional arguments — the same
// convention every phpurs FFI implementation already uses, including the
// func_num_args partial-application fallback. runFnN therefore applies
// its function saturated; mkFnN adapts a curried PureScript function to
// that shape.

$runFn0 = function ($fn) {
    return $fn();
};

$mkFn0 = function ($__fn) {
    return function () use ($__fn) {
        return $__fn(null);
    };
};

$runFn2 = function ($fn, $a = null, $b = null) use (&$runFn2) {
    if (func_num_args() < 3) {
        $__args = func_get_args();
        return function (...$more) use ($__args, &$runFn2) {
            return $runFn2(...array_merge($__args, $more));
        };
    }
    return $fn($a, $b);
};

$mkFn2 = function ($__fn) {
    $self = null;
    $self = function ($a = null, $b = null) use ($__fn, &$self) {
        if (func_num_args() < 2) {
            $__args = func_get_args();
            return function (...$more) use ($__args, &$self) {
                return $self(...array_merge($__args, $more));
            };
        }
        return $__fn($a)($b);
    };
    return $self;
};

$runFn3 = function ($fn, $a = null, $b = null, $c = null) use (&$runFn3) {
    if (func_num_args() < 4) {
        $__args = func_get_args();
        return function (...$more) use ($__args, &$runFn3) {
            return $runFn3(...array_merge($__args, $more));
        };
    }
    return $fn($a, $b, $c);
};

$mkFn3 = function ($__fn) {
    $self = null;
    $self = function ($a = null, $b = null, $c = null) use ($__fn, &$self) {
        if (func_num_args() < 3) {
            $__args = func_get_args();
            return function (...$more) use ($__args, &$self) {
                return $self(...array_merge($__args, $more));
            };
        }
        return $__fn($a)($b)($c);
    };
    return $self;
};

$runFn4 = function ($fn, $a = null, $b = null, $c = null, $d = null) use (&$runFn4) {
    if (func_num_args() < 5) {
        $__args = func_get_args();
        return function (...$more) use ($__args, &$runFn4) {
            return $runFn4(...array_merge($__args, $more));
        };
    }
    return $fn($a, $b, $c, $d);
};

$mkFn4 = function ($__fn) {
    $self = null;
    $self = function ($a = null, $b = null, $c = null, $d = null) use ($__fn, &$self) {
        if (func_num_args() < 4) {
            $__args = func_get_args();
            return function (...$more) use ($__args, &$self) {
                return $self(...array_merge($__args, $more));
            };
        }
        return $__fn($a)($b)($c)($d);
    };
    return $self;
};

$runFn5 = function ($fn, $a = null, $b = null, $c = null, $d = null, $e = null) use (&$runFn5) {
    if (func_num_args() < 6) {
        $__args = func_get_args();
        return function (...$more) use ($__args, &$runFn5) {
            return $runFn5(...array_merge($__args, $more));
        };
    }
    return $fn($a, $b, $c, $d, $e);
};

$mkFn5 = function ($__fn) {
    $self = null;
    $self = function ($a = null, $b = null, $c = null, $d = null, $e = null) use ($__fn, &$self) {
        if (func_num_args() < 5) {
            $__args = func_get_args();
            return function (...$more) use ($__args, &$self) {
                return $self(...array_merge($__args, $more));
            };
        }
        return $__fn($a)($b)($c)($d)($e);
    };
    return $self;
};

$runFn6 = function ($fn, $a = null, $b = null, $c = null, $d = null, $e = null, $f = null) use (&$runFn6) {
    if (func_num_args() < 7) {
        $__args = func_get_args();
        return function (...$more) use ($__args, &$runFn6) {
            return $runFn6(...array_merge($__args, $more));
        };
    }
    return $fn($a, $b, $c, $d, $e, $f);
};

$mkFn6 = function ($__fn) {
    $self = null;
    $self = function ($a = null, $b = null, $c = null, $d = null, $e = null, $f = null) use ($__fn, &$self) {
        if (func_num_args() < 6) {
            $__args = func_get_args();
            return function (...$more) use ($__args, &$self) {
                return $self(...array_merge($__args, $more));
            };
        }
        return $__fn($a)($b)($c)($d)($e)($f);
    };
    return $self;
};

$runFn7 = function ($fn, $a = null, $b = null, $c = null, $d = null, $e = null, $f = null, $g = null) use (&$runFn7) {
    if (func_num_args() < 8) {
        $__args = func_get_args();
        return function (...$more) use ($__args, &$runFn7) {
            return $runFn7(...array_merge($__args, $more));
        };
    }
    return $fn($a, $b, $c, $d, $e, $f, $g);
};

$mkFn7 = function ($__fn) {
    $self = null;
    $self = function ($a = null, $b = null, $c = null, $d = null, $e = null, $f = null, $g = null) use ($__fn, &$self) {
        if (func_num_args() < 7) {
            $__args = func_get_args();
            return function (...$more) use ($__args, &$self) {
                return $self(...array_merge($__args, $more));
            };
        }
        return $__fn($a)($b)($c)($d)($e)($f)($g);
    };
    return $self;
};

$runFn8 = function ($fn, $a = null, $b = null, $c = null, $d = null, $e = null, $f = null, $g = null, $h = null) use (&$runFn8) {
    if (func_num_args() < 9) {
        $__args = func_get_args();
        return function (...$more) use ($__args, &$runFn8) {
            return $runFn8(...array_merge($__args, $more));
        };
    }
    return $fn($a, $b, $c, $d, $e, $f, $g, $h);
};

$mkFn8 = function ($__fn) {
    $self = null;
    $self = function ($a = null, $b = null, $c = null, $d = null, $e = null, $f = null, $g = null, $h = null) use ($__fn, &$self) {
        if (func_num_args() < 8) {
            $__args = func_get_args();
            return function (...$more) use ($__args, &$self) {
                return $self(...array_merge($__args, $more));
            };
        }
        return $__fn($a)($b)($c)($d)($e)($f)($g)($h);
    };
    return $self;
};

$runFn9 = function ($fn, $a = null, $b = null, $c = null, $d = null, $e = null, $f = null, $g = null, $h = null, $i = null) use (&$runFn9) {
    if (func_num_args() < 10) {
        $__args = func_get_args();
        return function (...$more) use ($__args, &$runFn9) {
            return $runFn9(...array_merge($__args, $more));
        };
    }
    return $fn($a, $b, $c, $d, $e, $f, $g, $h, $i);
};

$mkFn9 = function ($__fn) {
    $self = null;
    $self = function ($a = null, $b = null, $c = null, $d = null, $e = null, $f = null, $g = null, $h = null, $i = null) use ($__fn, &$self) {
        if (func_num_args() < 9) {
            $__args = func_get_args();
            return function (...$more) use ($__args, &$self) {
                return $self(...array_merge($__args, $more));
            };
        }
        return $__fn($a)($b)($c)($d)($e)($f)($g)($h)($i);
    };
    return $self;
};

$runFn10 = function ($fn, $a = null, $b = null, $c = null, $d = null, $e = null, $f = null, $g = null, $h = null, $i = null, $j = null) use (&$runFn10) {
    if (func_num_args() < 11) {
        $__args = func_get_args();
        return function (...$more) use ($__args, &$runFn10) {
            return $runFn10(...array_merge($__args, $more));
        };
    }
    return $fn($a, $b, $c, $d, $e, $f, $g, $h, $i, $j);
};

$mkFn10 = function ($__fn) {
    $self = null;
    $self = function ($a = null, $b = null, $c = null, $d = null, $e = null, $f = null, $g = null, $h = null, $i = null, $j = null) use ($__fn, &$self) {
        if (func_num_args() < 10) {
            $__args = func_get_args();
            return function (...$more) use ($__args, &$self) {
                return $self(...array_merge($__args, $more));
            };
        }
        return $__fn($a)($b)($c)($d)($e)($f)($g)($h)($i)($j);
    };
    return $self;
};

$exports['runFn0'] = $runFn0;
$exports['mkFn0'] = $mkFn0;
$exports['runFn2'] = $runFn2;
$exports['mkFn2'] = $mkFn2;
$exports['runFn3'] = $runFn3;
$exports['mkFn3'] = $mkFn3;
$exports['runFn4'] = $runFn4;
$exports['mkFn4'] = $mkFn4;
$exports['runFn5'] = $runFn5;
$exports['mkFn5'] = $mkFn5;
$exports['runFn6'] = $runFn6;
$exports['mkFn6'] = $mkFn6;
$exports['runFn7'] = $runFn7;
$exports['mkFn7'] = $mkFn7;
$exports['runFn8'] = $runFn8;
$exports['mkFn8'] = $mkFn8;
$exports['runFn9'] = $runFn9;
$exports['mkFn9'] = $mkFn9;
$exports['runFn10'] = $runFn10;
$exports['mkFn10'] = $mkFn10;
return $exports;