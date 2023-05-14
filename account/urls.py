from django.urls import path
from account.views import SendPasswordResetEmailView, UserChangePasswordView, UserLoginView, UserProfileView, UserRegistrationView, UserPasswordResetView
from . import views

urlpatterns = [
    path('register/', UserRegistrationView.as_view(), name='register'),
    path('login', UserLoginView.as_view(), name='login'),
    path('profile/', UserProfileView.as_view(), name='profile'),
    path('changepassword/', UserChangePasswordView.as_view(), name='changepassword'),
    path('send-reset-password-email/', SendPasswordResetEmailView.as_view(), name='send-reset-password-email'),
    path('reset-password/<uid>/<token>/', UserPasswordResetView.as_view(), name='reset-password'),
    path('enquiry-list/', views.enquiryList, name='enquiry-list'),
    path('enquiry-detail/<str:pk>/', views.enquiryDetail, name='enquiry-detail'),
    path('enquiry-update/<str:pk>/', views.enquiryUpdate, name='enquiry-update'),
    path('enquiry-delete/<str:pk>/', views.enquiryDelete, name='enquiry-delete'),
    path('enquiry-create/', views.enquiryCreate, name='enquiry-create'),
    path('endoresment-create/', views.endoresmentCreate, name='endoresment-create'),
    path('endoresment-list/', views.endoresmentList, name='endoresment-list'),
    path('endoresment-detail/<str:pk>/', views.endoresmentDetail, name='endoresment-detail'),
    path('endoresment-update/<str:pk>/', views.endoresmentUpdate, name='endoresment-update'),
    path('endoresment-delete/<str:pk>/', views.endoresmentDelete, name='endoresment-delete'),
    path('check-user/', views.isUserAdmin, name='check-user'),
]