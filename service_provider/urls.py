from django.urls import include, path
from .views import BookingsServiceRequestsView, ComplaintViewSet, CompletedServiceRequestView, CustomerServiceRequestView, DeclineServiceView, DeductLeadBalanceView, FinancialOverviewView, OngoingServiceRequestView, PaymentListView, ResendOTPView, ServiceDetailsView, ServiceProviderLoginView, ServiceProviderPasswordForgotView, ServiceProviderPasswordForgotView, ServiceProviderRequestsView, ServiceProviderReviews, ServiceProviderViewSet, ServiceRegisterViewSet, ServiceRequestCompleteStatus, ServiceRequestInvoiceView, SetNewForgotPasswordView, SetNewPasswordView, VerifyOTPView
from rest_framework.routers import DefaultRouter
from rest_framework_simplejwt.views import TokenRefreshView
router = DefaultRouter()
router.register(r'service-registers', ServiceRegisterViewSet, basename='service-register')
router.register(r'complaints', ComplaintViewSet, basename='complaint')


urlpatterns = [
    path('login/', ServiceProviderLoginView.as_view(), name='service-provider-login'),
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),  # To refresh access token
    path('set-new-password/', SetNewPasswordView.as_view(), name='set-new-password'),
    #forgot password
    path('password-forgot/', ServiceProviderPasswordForgotView.as_view(), name='service-provider-password-forgot'),
    path('verify-otp/', VerifyOTPView.as_view(), name='verify_otp'),
    path('resend-otp/', ResendOTPView.as_view(), name='resend-otp'),
    path('password-reset/', SetNewForgotPasswordView.as_view(), name='service-provider-password-reset-confirm'),
    #profile update
    path('profile/', ServiceProviderViewSet.as_view({'get': 'retrieve', 'put': 'update','patch': 'partial_update'}), name='profile_update'),
    #service register,edit,lead balance
    path('', include(router.urls)),
    #service request
    path('service-requests/', ServiceProviderRequestsView.as_view(), name='service-provider-requests'),
    path('service-requests/details/', CustomerServiceRequestView.as_view(), name="details"),
    path('invoice/', ServiceRequestInvoiceView.as_view(), name="invoice"),
    #bookings and appointments
    path('bookings/', BookingsServiceRequestsView.as_view(), name="bookings"),
    path('service_details/', ServiceDetailsView.as_view(), name="service_details"),
    path('declinerequest/', DeclineServiceView.as_view(), name="decline_request"),
    #deduct lead
    path('deductlead/', DeductLeadBalanceView.as_view(), name="deductlead"),
    #complaints
    #path('', include(router.urls)),
    #Active services
    path('ongoing/', OngoingServiceRequestView.as_view(), name="ongoing"),
    path('completed/', CompletedServiceRequestView.as_view(), name="completed"),
    path('change-work-status/', ServiceRequestCompleteStatus.as_view(), name='check-work-status'),
    #transactions
    path('transactions/', PaymentListView.as_view(), name='payment-list'),
    path('financial/', FinancialOverviewView.as_view(), name='financial-overview'),
    path('reviews/', ServiceProviderReviews.as_view(), name='service-provider-reviews'),
    
]