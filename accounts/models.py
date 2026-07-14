from django.contrib.auth.models import User
from django.db import models


class Account(models.Model):
    """
    Role + ownership record linking a stock auth.User to this project's
    domain identifiers. Kept separate from AUTH_USER_MODEL (rather than a
    custom user model) because db.sqlite3 already has real dev data and
    swapping AUTH_USER_MODEL post-hoc is high-risk.
    """

    class Role(models.TextChoices):
        STUDENT = "student", "Student"
        UNIVERSITY = "university", "University"

    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name="account")
    role = models.CharField(max_length=20, choices=Role.choices)

    # Only one of these is populated, depending on role.
    student_id = models.CharField(max_length=255, null=True, blank=True, unique=True, db_index=True)
    university_id = models.CharField(max_length=255, null=True, blank=True, db_index=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self) -> str:
        return f"Account({self.user.email}, {self.role})"


class TOTPDevice(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name="totp_device")
    # Plaintext base32 secret. Follow-up hardening item before any production
    # deploy: encrypt at rest (e.g. a Fernet-encrypted field).
    secret = models.CharField(max_length=64)
    confirmed_at = models.DateTimeField(null=True, blank=True)
    last_used_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self) -> str:
        return f"TOTPDevice(user={self.user_id}, confirmed={bool(self.confirmed_at)})"


class TOTPBackupCode(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="totp_backup_codes")
    code_hash = models.CharField(max_length=64, db_index=True)
    used_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self) -> str:
        return f"TOTPBackupCode(user={self.user_id}, used={bool(self.used_at)})"


###-------------------------- Face Recognition - GRD --------------------------###

class FaceImage(models.Model):
    user = models.OneToOneField(
        Account,
        on_delete=models.CASCADE,
        related_name="face_images"
    )

    image = models.ImageField(upload_to="faces/")

    width = models.PositiveIntegerField()
    height = models.PositiveIntegerField()
    file_size = models.PositiveIntegerField()

    mime_type = models.CharField(max_length=50)

    captured_at = models.DateTimeField(auto_now_add=True)

    is_registration = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-captured_at"]


class FaceEmbedding(models.Model):
    user = models.ForeignKey(
        Account,
        on_delete=models.CASCADE
    )

    embedding = models.BinaryField()

    model_name = models.CharField(max_length=50)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]

class FaceVerificationLog(models.Model):
    VERIFICATION_REASON_CHOICES = [
        ("LOGIN", "Login"),
        ("REAUTH", "Reauthentication"),
        ("RESCAN", "Face Rescan"),
        ("VERIFY", "Verification"),
    ]
    user = models.ForeignKey(
        Account,
        on_delete=models.CASCADE
    )

    reason = models.CharField(
        max_length=20,
        choices=VERIFICATION_REASON_CHOICES,
        default="VERIFY",
    )

    similarity_score = models.FloatField()

    passed = models.BooleanField()

    captured_at = models.DateTimeField(auto_now_add=True)

    ip_address = models.GenericIPAddressField(
        null=True,
        blank=True
    )

    device = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-captured_at"]