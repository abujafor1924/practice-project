from django.conf import settings
from django.conf.urls.static import static
from django.contrib import admin
from django.urls import include, path
from drf_yasg import openapi
from drf_yasg.views import get_schema_view
from rest_framework import permissions

get_schema_view = get_schema_view(
    openapi.Info(
        title="Auth System",
        default_version="v1",
        description="Your API description",
        # terms_of_service="https://www.google.com/policies/terms/",
        contact=openapi.Contact(email="Z1yXo@example.com"),
        license=openapi.License(name="Your License"),
    ),
    public=True,
    permission_classes=(permissions.AllowAny,),
)

urlpatterns = [
    path("admin/", admin.site.urls),
    path("api/v1/", include("api.urls")),
    path(
        "",
        get_schema_view.with_ui("swagger", cache_timeout=0),
        name="schema-swagger-ui",
    ),
]

urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
