from django.contrib import admin

from accounts.models import Account, TOTPBackupCode, TOTPDevice


@admin.register(Account)
class AccountAdmin(admin.ModelAdmin):
    list_display = ("user", "role", "student_id", "university_id", "created_at")
    search_fields = ("user__email", "student_id", "university_id")
    list_filter = ("role",)


@admin.register(TOTPDevice)
class TOTPDeviceAdmin(admin.ModelAdmin):
    list_display = ("user", "confirmed_at", "last_used_at", "created_at")
    search_fields = ("user__email",)


@admin.register(TOTPBackupCode)
class TOTPBackupCodeAdmin(admin.ModelAdmin):
    list_display = ("user", "used_at", "created_at")
    search_fields = ("user__email",)


# ###-------------------------- Face Recognition - GRD --------------------------###

# from .models import (
#     FaceImage,
#     FaceEmbedding,
#     FaceVerificationLog,
# )


# @admin.register(FaceImage)
# class FaceImageAdmin(admin.ModelAdmin):
#     list_display = (
#         "user",
#         "mime_type",
#         "width",
#         "height",
#         "file_size",
#         "is_registration",
#         "captured_at",
#     )
#     list_filter = (
#         "is_registration",
#         "mime_type",
#         "captured_at",
#     )
#     search_fields = (
#         "user__email",
#         "user__username",
#     )
#     readonly_fields = (
#         "width",
#         "height",
#         "file_size",
#         "mime_type",
#         "captured_at",
#         "created_at",
#     )
#     ordering = ("-captured_at",)


# @admin.register(FaceEmbedding)
# class FaceEmbeddingAdmin(admin.ModelAdmin):
#     list_display = (
#         "user",
#         "model_name",
#         "created_at",
#     )
#     list_filter = (
#         "model_name",
#         "created_at",
#     )
#     search_fields = (
#         "user__email",
#         "user__username",
#         "model_name",
#     )
#     readonly_fields = (
#         "embedding",
#         "created_at",
#     )
#     ordering = ("-created_at",)


# @admin.register(FaceVerificationLog)
# class FaceVerificationLogAdmin(admin.ModelAdmin):
#     list_display = (
#         "user",
#         "reason",
#         "similarity_score",
#         "passed",
#         "ip_address",
#         "captured_at",
#     )
#     list_filter = (
#         "reason",
#         "passed",
#         "captured_at",
#     )
#     search_fields = (
#         "user__email",
#         "user__username",
#         "ip_address",
#     )
#     readonly_fields = (
#         "user",
#         "reason",
#         "similarity_score",
#         "passed",
#         "captured_at",
#         "ip_address",
#         "device",
#         "created_at",
#     )
#     ordering = ("-captured_at",)