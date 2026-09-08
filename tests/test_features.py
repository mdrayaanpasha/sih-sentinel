from workers.features import (
    coefficient_of_variation,
    consonant_ratio,
    inter_arrivals,
    outbound_inbound_ratio,
    shannon_entropy,
)


def test_entropy_gibberish_higher_than_word():
    assert shannon_entropy("kxqvwzptrlmn") > shannon_entropy("google")


def test_cv_regular_is_low():
    assert coefficient_of_variation([2.0, 2.0, 2.0, 2.0]) < 0.01
    assert coefficient_of_variation([1.0, 9.0, 2.0, 8.0]) > 0.3


def test_inter_arrivals_sorted_and_nonneg():
    assert inter_arrivals([10.0, 12.0, 14.0]) == [2.0, 2.0]
    assert inter_arrivals([14.0, 10.0, 12.0]) == [2.0, 2.0]  # unsorted input


def test_out_in_ratio():
    assert outbound_inbound_ratio(1000, 10) == 100.0
    assert outbound_inbound_ratio(1000, 0) == 1000.0  # no divide-by-zero


def test_consonant_ratio_bounds():
    assert 0.0 <= consonant_ratio("aeiou") <= 1.0
    assert consonant_ratio("bcdfg") == 1.0
