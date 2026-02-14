from __future__ import annotations

from pathlib import Path

import pandas as pd

RANDOM_STATE = 42
URL_ROWS_PER_CLASS = 30000
PHISHING_ONLY_ROWS = 45000
ARABIC_AUG_ROWS_PER_CLASS = 850


def _read_csv_with_fallback(path: Path, encodings: tuple[str, ...]) -> pd.DataFrame:
    last_error: Exception | None = None
    for enc in encodings:
        try:
            return pd.read_csv(path, encoding=enc)
        except UnicodeDecodeError as exc:
            last_error = exc
    if last_error is not None:
        raise last_error
    return pd.read_csv(path)


def _to_binary_label(value) -> int | None:
    if pd.isna(value):
        return None

    text = str(value).strip().lower()
    unsafe_labels = {
        "1",
        "spam",
        "unsafe",
        "malicious",
        "phishing",
        "phish",
        "bad",
        "scam",
        "fraud",
        "defacement",
        "malware",
        "suspicious",
    }
    safe_labels = {
        "0",
        "ham",
        "safe",
        "benign",
        "legitimate",
        "good",
        "normal",
    }

    if text in unsafe_labels:
        return 1
    if text in safe_labels:
        return 0
    return None


def _sample_by_class(frame: pd.DataFrame, max_per_class: int) -> pd.DataFrame:
    if max_per_class <= 0 or frame.empty:
        return frame

    sampled_parts = []
    for label in sorted(frame["label"].dropna().unique().tolist()):
        subset = frame[frame["label"] == int(label)]
        if len(subset) > max_per_class:
            subset = subset.sample(n=max_per_class, random_state=RANDOM_STATE)
        sampled_parts.append(subset)

    if not sampled_parts:
        return frame

    return pd.concat(sampled_parts, ignore_index=True)


def _prepare_messages_dataset(path: Path) -> pd.DataFrame:
    if not path.is_file():
        return pd.DataFrame(columns=["text", "label", "source"])

    data = _read_csv_with_fallback(path, ("utf-8", "utf-8-sig", "cp1252", "latin-1"))
    if "text" not in data.columns or "label" not in data.columns:
        raise ValueError(f"{path} must contain 'text' and 'label' columns.")

    out = pd.DataFrame()
    out["text"] = data["text"].astype(str)
    out["label"] = data["label"].map(_to_binary_label)
    out["source"] = "messages"
    return out


def _prepare_spam_dataset(path: Path) -> pd.DataFrame:
    if not path.is_file():
        return pd.DataFrame(columns=["text", "label", "source"])

    data = _read_csv_with_fallback(path, ("utf-8", "utf-8-sig", "cp1252", "latin-1"))

    text_col = "v2" if "v2" in data.columns else ("text" if "text" in data.columns else None)
    label_col = "v1" if "v1" in data.columns else ("label" if "label" in data.columns else None)
    if text_col is None or label_col is None:
        raise ValueError(f"{path} must contain either (v1,v2) or (label,text) columns.")

    out = pd.DataFrame()
    out["text"] = data[text_col].astype(str)
    out["label"] = data[label_col].map(_to_binary_label)
    out["source"] = "spam_csv"
    return out


def _prepare_arabic_file_dataset(path: Path) -> pd.DataFrame:
    if not path.is_file():
        return pd.DataFrame(columns=["text", "label", "source"])

    data = _read_csv_with_fallback(path, ("utf-8", "utf-8-sig", "cp1256", "cp1252", "latin-1"))
    if "text" not in data.columns or "label" not in data.columns:
        return pd.DataFrame(columns=["text", "label", "source"])

    out = pd.DataFrame()
    out["text"] = data["text"].astype(str)
    out["label"] = data["label"].map(_to_binary_label)
    out["source"] = "arabic_file"
    return out


def _prepare_url_dataset(
    path: Path,
    source: str,
    label_col_candidates: tuple[str, ...],
    default_label: int | None = None,
    rows_per_class: int = 0,
) -> pd.DataFrame:
    if not path.is_file():
        return pd.DataFrame(columns=["text", "label", "source"])

    data = _read_csv_with_fallback(path, ("utf-8", "utf-8-sig", "cp1252", "latin-1"))

    url_col = None
    for candidate in ("url", "URL", "link"):
        if candidate in data.columns:
            url_col = candidate
            break
    if url_col is None:
        return pd.DataFrame(columns=["text", "label", "source"])

    label_col = None
    for candidate in label_col_candidates:
        if candidate in data.columns:
            label_col = candidate
            break

    out = pd.DataFrame()
    out["text"] = data[url_col].astype(str)

    if label_col is not None:
        out["label"] = data[label_col].map(_to_binary_label)
    elif default_label in (0, 1):
        out["label"] = int(default_label)
    else:
        out["label"] = None

    out["source"] = source
    out = out.dropna(subset=["text", "label"]).copy()
    out["label"] = out["label"].astype(int)

    if rows_per_class > 0:
        out = _sample_by_class(out, rows_per_class)

    return out


def _build_arabic_augmentation_dataset() -> pd.DataFrame:
    # This synthetic set adds broad Arabic safe/unsafe language coverage to reduce false positives.
    safe_terms = [
        "موعد",
        "اجتماع",
        "فريق",
        "العمل",
        "تأكيد",
        "جدول",
        "الأعمال",
        "منصة",
        "دعوة",
        "تقويم",
        "مكتب",
        "مشروع",
        "تقرير",
        "مرفق",
        "شكرا",
        "تواصل",
        "مراجعة",
        "جلسة",
        "استشارة",
        "مناقشة",
        "تعاون",
        "تدريب",
        "تعليم",
        "جامعة",
        "كلية",
        "دراسة",
        "محاضرة",
        "واجب",
        "امتحان",
        "إشعار",
        "استلام",
        "شحنة",
        "طلب",
        "فاتورة",
        "دفع",
        "استرداد",
        "حجز",
        "تذكرة",
        "عيادة",
        "طبيب",
        "موظف",
        "إدارة",
        "قسم",
        "تذكير",
        "زيارة",
        "عميل",
        "خدمة",
        "دعم",
        "مساعدة",
        "اتصال",
        "مكالمة",
        "رسالة",
        "بريد",
        "وثيقة",
        "اعتماد",
        "تفويض",
        "نموذج",
        "تسليم",
        "موافقة",
        "صيانة",
        "نظام",
        "حساب",
        "آمن",
        "نجاح",
        "الساعة",
        "غدا",
        "اليوم",
        "الثلاثاء",
        "الأربعاء",
        "الخميس",
        "السبت",
        "الأحد",
    ]

    unsafe_terms = [
        "كلمة المرور",
        "رمز التحقق",
        "otp",
        "تحقق",
        "التحقق",
        "تأكيد الحساب",
        "حسابك",
        "إيقاف",
        "تعليق",
        "تجميد",
        "فوري",
        "عاجل",
        "اضغط هنا",
        "انقر",
        "رابط",
        "تسجيل الدخول",
        "دخول الآن",
        "بنك",
        "محفظة",
        "بطاقة",
        "دفع فوري",
        "مكافأة",
        "جائزة",
        "ربحت",
        "اربح",
        "استلام الجائزة",
        "تحديث البيانات",
        "بياناتك",
        "الهوية",
        "رقم سري",
        "pin",
        "تحويل",
        "فاتورة متأخرة",
        "رسوم",
        "استرداد عاجل",
        "إلغاء",
        "تنبيه أمني",
        "نشاط مشبوه",
        "تم اختراق",
        "حساب مهدد",
        "احم حسابك",
        "أرسل",
        "شارك",
        "أدخل",
        "سجل",
        "افتح",
        "تحميل",
        "تطبيق",
        "هدية",
        "عرض محدود",
        "مجاني",
        "نتفلكس",
        "بايبال",
        "جوجل",
        "مايكروسوفت",
        "واتساب",
        "تلجرام",
        "حساب بنكي",
        "رقم البطاقة",
        "cvv",
        "التحويل الآن",
        "خلال 24 ساعة",
        "سيتم الإغلاق",
    ]

    brands = ["جوجل", "مايكروسوفت", "بايبال", "نتفلكس", "واتساب", "تلجرام"]
    days = ["الأحد", "الاثنين", "الثلاثاء", "الأربعاء", "الخميس"]
    times = ["09:00", "10:00", "11:30", "13:00", "15:00", "18:30"]

    safe_templates = [
        "نؤكد {a} {b} يوم {day} الساعة {time} ضمن {c}.",
        "يرجى حضور {a} الخاصة بـ {b} في {time}.",
        "تم اعتماد {a} ومشاركة {b} مع {c}.",
        "هذا إشعار {a} بخصوص {b} وسيتم المتابعة عبر {c}.",
        "رسالة {a} عادية تتعلق بـ {b} و{c}.",
        "تم تحديث {a} بنجاح بخصوص {b} ضمن {c}.",
        "يرجى مراجعة {a} و{b} قبل {time}.",
        "هذه دعوة {a} لفريق {b} على منصة {c}.",
    ]

    unsafe_templates = [
        "رسالة عاجلة: {a}. يجب {b} الآن وإلا {c}.",
        "تم رصد نشاط مشبوه. {a} عبر الرابط و{b} فورا.",
        "لقد ربحت جائزة من {brand}. {a} ثم {b}.",
        "حسابك معرض للإيقاف خلال 24 ساعة. {a} و{b}.",
        "تنبيه أمني من {brand}: {a} ثم {b} الآن.",
        "لتفادي الإغلاق، {a} و{b} قبل الساعة {time}.",
        "طلب فوري: {a} لإكمال {b} واستلام {c}.",
        "نحتاج {a} الآن، ثم {b} لتأكيد {c}.",
    ]

    rows = []

    for i in range(ARABIC_AUG_ROWS_PER_CLASS):
        a = safe_terms[i % len(safe_terms)]
        b = safe_terms[(i * 7 + 3) % len(safe_terms)]
        c = safe_terms[(i * 11 + 5) % len(safe_terms)]
        day = days[i % len(days)]
        time = times[i % len(times)]
        tpl = safe_templates[i % len(safe_templates)]
        rows.append({"text": tpl.format(a=a, b=b, c=c, day=day, time=time), "label": 0, "source": "arabic_aug"})

    for i in range(ARABIC_AUG_ROWS_PER_CLASS):
        a = unsafe_terms[i % len(unsafe_terms)]
        b = unsafe_terms[(i * 5 + 2) % len(unsafe_terms)]
        c = unsafe_terms[(i * 9 + 4) % len(unsafe_terms)]
        brand = brands[i % len(brands)]
        time = times[i % len(times)]
        tpl = unsafe_templates[i % len(unsafe_templates)]
        rows.append(
            {
                "text": tpl.format(a=a, b=b, c=c, brand=brand, time=time),
                "label": 1,
                "source": "arabic_aug",
            }
        )

    return pd.DataFrame(rows)


def load_training_dataset(base_dir: str | Path = ".") -> pd.DataFrame:
    root = Path(base_dir)

    parts = [
        _prepare_messages_dataset(root / "messages.csv"),
        _prepare_spam_dataset(root / "spam" / "spam.csv"),
        _prepare_arabic_file_dataset(root / "spam" / "arabic_expanded.csv"),
        _build_arabic_augmentation_dataset(),
        _prepare_url_dataset(
            root / "URL dataset.csv",
            source="url_dataset",
            label_col_candidates=("type", "Type", "label", "Label"),
            rows_per_class=URL_ROWS_PER_CLASS,
        ),
        _prepare_url_dataset(
            root / "Phishing URLs.csv",
            source="phishing_urls",
            label_col_candidates=("Type", "type", "label", "Label"),
            default_label=1,
            rows_per_class=PHISHING_ONLY_ROWS,
        ),
    ]

    data = pd.concat(parts, ignore_index=True)
    if data.empty:
        raise ValueError("No training rows were loaded.")

    data = data.dropna(subset=["text", "label"]).copy()
    data["text"] = data["text"].astype(str).str.strip()
    data = data[data["text"].str.len() > 0]
    data["label"] = data["label"].astype(int)

    # Keep one copy of exact duplicate rows.
    data = data.drop_duplicates(subset=["text", "label"], keep="first")
    data = data.reset_index(drop=True)
    return data
