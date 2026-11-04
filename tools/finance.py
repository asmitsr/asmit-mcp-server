"""Finance tools: expense splitting, balance settlement, currency.

Money is handled in integer poisha (amount * 100), never floats.
Currency rates come from a free no-key API and are cached for 5
minutes in memory (see core.cache); rates are indicative only.
"""

import re

from core.cache import CURRENCY_CACHE
from core.errors import failure, success
from core.http import get_json
from core.validation import (
    ValidationError,
    req_amount,
    req_balances,
    req_members,
    req_str,
)

_CURRENCY_CODE = re.compile(r"^[A-Za-z]{3}$")


def _currency_code(value, field):
    value = req_str(value, field, max_len=10).upper()
    if not _CURRENCY_CODE.match(value):
        raise ValidationError(f"{field} must be a 3-letter currency code")
    return value


def _simplify(cents):
    """Greedy creditor/debtor matching; returns settlement dicts."""
    creditors = sorted(((m, c) for m, c in cents.items() if c > 0),
                       key=lambda x: -x[1])
    debtors = sorted(((m, -c) for m, c in cents.items() if c < 0),
                     key=lambda x: -x[1])
    settlements = []
    ci = di = 0
    while ci < len(creditors) and di < len(debtors):
        cm, camt = creditors[ci]
        dm, damt = debtors[di]
        pay = min(camt, damt)
        settlements.append({"from": dm, "to": cm, "amount": pay / 100})
        creditors[ci] = (cm, camt - pay)
        debtors[di] = (dm, damt - pay)
        if creditors[ci][1] == 0:
            ci += 1
        if debtors[di][1] == 0:
            di += 1
    return settlements


def split_expense(total_amount: float, members: list[str], paid_by: str,
                  custom_shares: dict[str, float] | None = None) -> str:
    """Split an expense and simplify who owes whom.

    Equal split: the remainder poisha go to the first members, so the
    shares always add up exactly. Custom split: shares must sum exactly
    to the total, otherwise a validation error is returned.
    """
    total = round(req_amount(total_amount, "total_amount") * 100)
    members = req_members(members)
    paid_by = req_str(paid_by, "paid_by", max_len=100)
    if paid_by not in members:
        raise ValidationError("members must include paid_by")
    if custom_shares is not None:
        if not isinstance(custom_shares, dict):
            raise ValidationError("custom_shares must be an object")
        shares = {}
        for member in members:
            value = custom_shares.get(member, 0)
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise ValidationError("custom shares must be numbers")
            shares[member] = round(value * 100)
        if sum(shares.values()) != total:
            raise ValidationError("custom shares do not sum to the total")
    else:
        base, remainder = divmod(total, len(members))
        shares = {m: base + (1 if i < remainder else 0)
                  for i, m in enumerate(members)}
    paid = {m: (total if m == paid_by else 0) for m in members}
    balances = {m: paid[m] - shares[m] for m in members}
    return success({
        "shares": {m: v / 100 for m, v in shares.items()},
        "balances": {m: v / 100 for m, v in balances.items()},
        "settlements": _simplify(balances),
    })


def settle_balances(balances: dict[str, float]) -> str:
    """Simplify any set of balances into the fewest payments.

    balances maps each person to what they are owed (+) or owe (-);
    the values must sum to zero. Money is handled in integer poisha.
    """
    balances = req_balances(balances)
    cents = {m: round(v * 100) for m, v in balances.items()}
    if sum(cents.values()) != 0:
        raise ValidationError("balances must sum to zero")
    settlements = _simplify(cents)
    return success({"settlements": settlements,
                    "payment_count": len(settlements)})


def convert_currency(amount: float, from_currency: str, to_currency: str) -> str:
    """Convert an amount between currencies using a free no-key rate API.

    Rates are indicative, from exchangerate-api.com, and are not
    financial advice. Rates are cached in memory for 5 minutes.
    """
    amount = req_amount(amount, "amount")
    src = _currency_code(from_currency, "from_currency")
    dst = _currency_code(to_currency, "to_currency")
    rates = CURRENCY_CACHE.get(src)
    cached = rates is not None
    if not cached:
        data, error = get_json(
            f"https://api.exchangerate-api.com/v4/latest/{src}")
        if error:
            return failure(error[0], error[1])
        rates = data.get("rates") or {}
        CURRENCY_CACHE.set(src, rates)
    if dst not in rates:
        raise ValidationError(f"unknown currency: {dst}")
    return success({"amount": amount, "from": src, "to": dst,
                    "converted": round(amount * rates[dst], 2),
                    "rate": rates[dst], "cached": cached,
                    "note": "Indicative rate only."})
