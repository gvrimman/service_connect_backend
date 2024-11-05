from django.urls import include, path
from .views import ActiveServiceRequestDetailView, CategoryListView, CompletedServiceRequestListView, CustomerLoginView, CustomerPasswordForgotView, CustomerReviewView, PopularServiceDetailView, RegisterComplaintView, RegistrationVerifyOTPView, CustomerViewSet, OngoingServiceRequestListView, RegisterView, ResendOTPView, ServiceProviderDetailView, ServiceProviderListView, ServiceProviderSearchView, ServiceRequestCreateView, ServiceRequestDetailView, ServiceRequestInvoiceDetailView, SetNewForgotPasswordView, SubcategoryListView, TopServiceProviderView, TransactionList, UnifiedSearchView, VerifyOTPView, save_location
from rest_framework.routers import DefaultRouter
from rest_framework_simplejwt.views import TokenRefreshView


urlpatterns = [
    path('register/', RegisterView.as_view(), name='register_customer'),
    path('verify-otp-registration/', RegistrationVerifyOTPView.as_view(), name='verify-otp'),
    path('resend-otp/', ResendOTPView.as_view(), name='resend-otp'),
    #login
    path('login/', CustomerLoginView.as_view(), name='customer-login'),
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),  # To refresh access token
    #forgot password
    path('password-forgot/', CustomerPasswordForgotView.as_view(), name='customer-password-forgot'),
    path('verify-otp/', VerifyOTPView.as_view(), name='verify_otp'),
    path('password-reset/', SetNewForgotPasswordView.as_view(), name='customer-password-reset-confirm'),
    #location
    path('save-location/', save_location, name='save_location'),
    #dashboard
    path('dashboard/popularservices/all/', PopularServiceDetailView.as_view(), name='services-with-reviews'),
    path('dashboard/top-service-providers/', TopServiceProviderView.as_view(), name='top_service_providers'),
    #profile update
    path('profile/', CustomerViewSet.as_view({'get': 'retrieve', 'put': 'update','patch': 'partial_update'}), name='profile_update'),
    #category, subcategory, service_providers_list, detailed view of service providers
    path('categories/', CategoryListView.as_view(), name='category-list'),
    path('categories/<int:category_id>/subcategories/', SubcategoryListView.as_view(), name='subcategory-list'),
    path('subcategories/<int:subcategory_id>/service-providers/', ServiceProviderListView.as_view(), name='serviceprovider-list'),
    path('service_provider/<int:id>/', ServiceProviderDetailView.as_view(), name='service_provider_detail'),
    #search_functionality
    path('search/', UnifiedSearchView.as_view(), name='unified-search'),
    path('service-providers/search/', ServiceProviderSearchView.as_view(), name='serviceprovider-search'),
    #service request upto booking details
    path('service-request/', ServiceRequestCreateView.as_view(), name='service-request-create'),
    path('view-request-user/', ServiceRequestDetailView.as_view(), name='view-request-user'),
    path('service-request-invoice/', ServiceRequestInvoiceDetailView.as_view(), name='service-request-invoice-detail'),
    #Actice services
    path('service-requests/ongoing/', OngoingServiceRequestListView.as_view(), name='ongoing-service-requests'),
    path('service-requests/completed/', CompletedServiceRequestListView.as_view(), name='completed-service-requests'),
    path('service-requests/<int:id>/', ActiveServiceRequestDetailView.as_view(), name='service-request-detail'),
    #customer review
    path('review/', CustomerReviewView.as_view(), name='customer-review'),
    # Complaint Form
    path('complaint/', RegisterComplaintView.as_view(), name='create-complaint'),
    #transaction list
    path('transactions/', TransactionList.as_view(), name='transactions'),

]