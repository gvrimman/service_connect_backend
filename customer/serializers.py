import re
from django.contrib.auth import get_user_model
import phonenumbers
from phonenumbers import parse, NumberParseException
from rest_framework import serializers
from django.core.exceptions import ValidationError
from django.contrib.auth import authenticate
from app1.models import Category, Complaint, Country_Codes, CurrentLocation, Customer, CustomerReview, Invoice, Payment, ServiceProvider, ServiceRegister, ServiceRequest, Subcategory
from django.contrib.auth.password_validation import validate_password
from django.db.models import Avg, Min, Max, Count
from django.core.validators import validate_email
from rest_framework.exceptions import ValidationError

User = get_user_model()

#registration and otp verification
class RegisterSerializer(serializers.ModelSerializer):
    email_or_phone = serializers.CharField(required=True)
    password = serializers.CharField(write_only=True, min_length=8)
    confirm_password = serializers.CharField(write_only=True, min_length=8)
    
    
    class Meta:
        model = User
        fields = ['email_or_phone', 'password', 'confirm_password']
    
    def validate_password(self, value):
        # Use Django's built-in password validators to validate the password
        validate_password(value)

        # Custom validation for password complexity
        if not re.search(r'[A-Z]', value):
            raise serializers.ValidationError("Password must contain at least one uppercase letter.")
        if not re.search(r'[a-z]', value):
            raise serializers.ValidationError("Password must contain at least one lowercase letter.")
        if not re.search(r'\d', value):
            raise serializers.ValidationError("Password must contain at least one digit.")
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', value):
            raise serializers.ValidationError("Password must contain at least one special character.")

        return value

    def validate(self, data):
        email_or_phone = data.get('email_or_phone')
        password = data.get('password')
        confirm_password = data.get('confirm_password')

        # Check if both passwords match
        if password != confirm_password:
            raise serializers.ValidationError("Passwords do not match")

        # Validate email or phone number format
        if '@' in email_or_phone:
            # Check if email is already registered
            validate_email(email_or_phone)
            if User.objects.filter(email=email_or_phone).exists():
                raise serializers.ValidationError("Email is already in use")
        else:
            # Check if phone number is already registered
            #if User.objects.filter(phone_number=email_or_phone).exists():
            try:
                parsed_number = phonenumbers.parse(email_or_phone, None)
                if not phonenumbers.is_valid_number(parsed_number):
                    raise ValidationError("Invalid phone number.")
            except phonenumbers.NumberParseException:
                raise ValidationError("Invalid phone number format.")

            fullnumber=phonenumbers.parse(email_or_phone,None)
            try:
                code=Country_Codes.objects.get(calling_code="+"+str(fullnumber.country_code))
            except Country_Codes.DoesNotExist:
                raise serializers.ValidationError("Can't idntify country code")
            if User.objects.filter(phone_number=str(fullnumber.national_number),country_code=code).exists():    
                raise serializers.ValidationError("Phone number is already in use")

        return data

    def create(self, validated_data):
        email_or_phone = validated_data.get('email_or_phone')
        password = validated_data.get('password')

        # Create user based on whether email or phone is provided
        if '@' in email_or_phone:
            #user = User.objects.create_user(email=email_or_phone, password=password)
            user = User.objects.create(email=email_or_phone)
        else:
            #user = User.objects.create_user(phone_number=email_or_phone, password=password)
            fullnumber=phonenumbers.parse(email_or_phone,None)
            code=Country_Codes.objects.get(calling_code="+"+str(fullnumber.country_code))
            number=str(fullnumber.national_number)
            user = User.objects.create(country_code=code,phone_number=number)
        
        user.set_password(password)
        # Ensure that is_customer is always set to True during registration
        user.is_active = False  # User is inactive until OTP is verified
        user.is_customer = True
        user.save()

        if user.is_customer:
            Customer.objects.create(user=user)

        return user
    
#resend otp
class ResendOTPSerializer(serializers.Serializer):
    email_or_phone = serializers.CharField(required=True)

    def validate(self, data):
        email_or_phone = data.get('email_or_phone')

        # Check if the user exists with either email or phone
        if '@' in email_or_phone:
            if not User.objects.filter(email=email_or_phone).exists():
                raise serializers.ValidationError("User with this email does not exist.")
        else:
            try:
                parsed_number = phonenumbers.parse(email_or_phone, None)
                if not phonenumbers.is_valid_number(parsed_number):
                    raise ValidationError("Invalid phone number.")
            except phonenumbers.NumberParseException:
                raise ValidationError("Invalid phone number format.")

            fullnumber=phonenumbers.parse(email_or_phone,None)
            try:
                code=Country_Codes.objects.get(calling_code="+"+str(fullnumber.country_code))
            except Country_Codes.DoesNotExist:
                raise serializers.ValidationError("Can't idntify country code")
            if not User.objects.filter(phone_number=str(fullnumber.national_number),country_code=code).exists():
            #if not User.objects.filter(phone_number=email_or_phone).exists():
                raise serializers.ValidationError("User with this phone number does not exist.")

        return data

    def get_user(self):
        email_or_phone = self.validated_data['email_or_phone']
        if '@' in email_or_phone:
            return User.objects.get(email=email_or_phone)
        else:
            fullnumber=phonenumbers.parse(email_or_phone,None)
            code=Country_Codes.objects.get(calling_code="+"+str(fullnumber.country_code))
            number=str(fullnumber.national_number)
            return User.objects.get(country_code=code,phone_number=number)

#login customer
class CustomerLoginSerializer(serializers.Serializer):
    email_or_phone = serializers.CharField(required=True)
    password = serializers.CharField(required=True, write_only=True)
    
    def validate(self, attrs):
        email_or_phone = attrs.get('email_or_phone')
        password = attrs.get('password')

        # Validate that either email or phone and password are provided
        if not email_or_phone:
            raise serializers.ValidationError('Email or phone is required.')
        if not password:
            raise serializers.ValidationError('Password is required.')

        # Try to authenticate the user using email or phone number
        user = None
        if '@' in email_or_phone:
            # If input is email
            user = authenticate(username=email_or_phone, password=password)
        else:
            # If input is phone number
            try:
                #user = User.objects.get(phone_number=email_or_phone)
                fullnumber=phonenumbers.parse(email_or_phone,None)
                code=Country_Codes.objects.get(calling_code="+"+str(fullnumber.country_code))
                number=str(fullnumber.national_number)
                user = User.objects.get(phone_number=number,country_code=code)
                if not user.check_password(password):
                    raise serializers.ValidationError('Invalid credentials.')
            except phonenumbers.phonenumberutil.NumberParseException:
                raise serializers.ValidationError('Wrong phone number or email format')    
            except User.DoesNotExist:
                raise serializers.ValidationError('Invalid login credentials.')

        if user is None or not user.is_customer:
            raise serializers.ValidationError('Invalid login credentials or not a customer.')

        attrs['user'] = user
        return attrs    

#forgot password and reset password
class CustomerPasswordForgotSerializer(serializers.Serializer):
    email_or_phone = serializers.CharField(required=True)

    def validate_email_or_phone(self, value):
        """
        This function will check if the provided value is either a valid email or a phone number.
        For now, we assume the input is either an email or phone number.
        """
        if '@' in value:
            # Validate as email
            if not User.objects.filter(email=value, is_customer=True).exists():
                raise serializers.ValidationError("This email is not registered with any customer.")
        else:
            try:
                # Parse and validate phone number
                fullnumber = phonenumbers.parse(value, None)
                if not phonenumbers.is_valid_number(fullnumber):
                    raise serializers.ValidationError("Invalid phone number format.")
                
                # Extract the country code and national number
                code = "+" + str(fullnumber.country_code)
                number = str(fullnumber.national_number)

                # Retrieve the country code record from Country_Codes
                country_code_obj = Country_Codes.objects.get(calling_code=code)

                # Debugging: Print the parsed country code and national number
                print(f"Country Code: {country_code_obj}, Phone Number: {number}")

                # Check if the phone number exists with the given country code
                if not User.objects.filter(phone_number=number, country_code=country_code_obj, is_customer=True).exists():
                    raise serializers.ValidationError("This phone number is not registered with any customer.")
                
            except phonenumbers.NumberParseException:
                raise serializers.ValidationError("Invalid phone number or email format.")


        return value     

class SetNewPasswordSerializer(serializers.Serializer):
    email_or_phone = serializers.CharField(required=True)  # Added this field
    new_password = serializers.CharField(required=True, write_only=True)
    confirm_password = serializers.CharField(required=True, write_only=True)
    
    def validate_new_password(self, value):
        # Use Django's password validators to validate the password
        validate_password(value)

        # Custom validation for password complexity
        if not re.search(r'[A-Z]', value):
            raise serializers.ValidationError("Password must contain at least one uppercase letter.")
        if not re.search(r'[a-z]', value):
            raise serializers.ValidationError("Password must contain at least one lowercase letter.")
        if not re.search(r'\d', value):
            raise serializers.ValidationError("Password must contain at least one digit.")
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', value):
            raise serializers.ValidationError("Password must contain at least one special character.")


        return value

    def validate(self, attrs):
        if attrs['new_password'] != attrs['confirm_password']:
            raise serializers.ValidationError("Passwords do not match")
        return attrs
    

#location
class CurrentLocationSerializer(serializers.ModelSerializer):
    class Meta:
        model = CurrentLocation
        fields = ['user', 'country', 'state', 'city', 'address', 'landmark', 'pincode', 'latitude', 'longitude']  
        
#dashboard
#popular services
class PopularServiceDetailSerializer(serializers.ModelSerializer):
    subcategory_title = serializers.CharField(source='subcategory.title', read_only=True)
    reviews_count = serializers.SerializerMethodField()
    rating = serializers.SerializerMethodField()
    amount = serializers.SerializerMethodField()
    image_url = serializers.ImageField(source='image', read_only=True)

    class Meta:
        model = ServiceRegister
        fields = ['subcategory_title', 'reviews_count', 'rating', 'amount', 'image_url']

    def get_reviews_count(self, obj):
        return CustomerReview.objects.filter(service_request__service=obj).count()

    def get_rating(self, obj):
        avg_rating = CustomerReview.objects.filter(service_request__service=obj).aggregate(avg_rating=Avg('rating'))['avg_rating']
        return round(avg_rating, 1) if avg_rating is not None else None

    def get_amount(self, obj):
        invoices = Invoice.objects.filter(service_register=obj, invoice_type='service_request', payment_status='paid')
        min_amount = invoices.aggregate(Min('total_amount'))['total_amount__min']
        max_amount = invoices.aggregate(Max('total_amount'))['total_amount__max']

        if min_amount and max_amount:
            return f"{min_amount}-{max_amount}" if min_amount != max_amount else str(min_amount)
        return None


# top service providers
class TopServiceProviderSerializer(serializers.ModelSerializer):
    full_name = serializers.CharField()
    profile_image = serializers.SerializerMethodField()
    service_provider_id = serializers.SerializerMethodField()
    custom_id = serializers.SerializerMethodField()

    class Meta:
        model = User  
        fields = ['service_provider_id','custom_id','full_name', 'profile_image']


    def get_custom_id(self, obj):
        # Get the custom ID of the associated ServiceProvider, if available
        service_provider = obj.service_provider.first()
        return service_provider.custom_id if service_provider else None


    def get_profile_image(self, obj):
        # Get the first associated ServiceProvider instance, if available
        service_provider = obj.service_provider.first()
        return service_provider.profile_image.url if service_provider and service_provider.profile_image else None

    def get_service_provider_id(self, obj):
        # Get the ID of the associated ServiceProvider, if available
        service_provider = obj.service_provider.first()
        return service_provider.id if service_provider else None

          
#for profile creation of customers
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = [
            'full_name',
            'address', 
            'landmark',
            'pin_code',
            'district',
            'state',
            'watsapp',
            'email',
            'country_code',
            'phone_number'
        ]

# Serializer for the Customer model
class CustomerSerializer(serializers.ModelSerializer):
    user = UserSerializer()

    class Meta:
        model = Customer
        fields = [
            "user",
            "profile_image",
            "date_of_birth",
            "gender",
            "accepted_terms"  # Add this field if it's part of Customer
        ]

    def create(self, validated_data):
        # Extract the nested user data from the validated data
        user_data = validated_data.pop('user')

        # Check if accepted_terms is False
        if not validated_data.get('accepted_terms'):
            raise ValidationError({"accepted_terms": "You must accept the terms and conditions to create a profile."})

        # Create the User and Customer instances
        user = User.objects.create(**user_data)
        customer = Customer.objects.create(user=user, **validated_data)
        return customer

    def update(self, instance, validated_data):
        # Extract user data and handle separately
        user_data = validated_data.pop('user', None)

        # Update customer fields
        for attr, value in validated_data.items():
            setattr(instance, attr, value)

        # Handle User fields separately
        if user_data:
            user = instance.user
            for attr, value in user_data.items():
                setattr(user, attr, value)
            user.save()

        # Save the customer instance with updated data
        instance.save()
        return instance


#view category subcategory and service providers
class CategorySerializer(serializers.ModelSerializer):
    class Meta:
        model = Category
        fields = ['id', 'title', 'description', 'image']

class SubcategorySerializer(serializers.ModelSerializer):
    class Meta:
        model = Subcategory
        fields = ['id', 'title', 'description', 'image']

class ServiceProviderSerializer(serializers.ModelSerializer):
     # Fetch the full name from the related User model
    full_name = serializers.CharField(source='user.full_name') 
    
    
    # Fetch the amount from the ServiceRegister model
    amount_forthis_service = serializers.SerializerMethodField()
    
    # Fetch the rating (assuming it's available in ServiceProvider or related models)
    rating = serializers.SerializerMethodField()

    class Meta:
        model = ServiceProvider
        fields = ['id', 'full_name', 'profile_image','amount_forthis_service', 'rating']

    def get_amount_forthis_service(self, obj):
        """Retrieve the average amount of services for the specific subcategory ID."""
        subcategory_id = self.context.get('subcategory_id')  # Get subcategory_id from context

        if not subcategory_id:
            return 0.00  # Return 0 if no subcategory ID is provided

        # Get all services registered by this service provider that match the subcategory
        services = ServiceRegister.objects.filter(service_provider=obj, subcategory_id=subcategory_id)

        if not services.exists():
            return 0.00  # Return 0 if there are no services for that subcategory

        # Calculate the average amount of all invoices related to the services of this service provider
        average = (
            Invoice.objects.filter(service_request__service__in=services)
            .aggregate(Avg('total_amount'))
            .get('total_amount__avg')
        )

        return round(average, 2) if average is not None else 0.00  # Return the rounded average

    
    def get_rating(self, obj):
        # Get all reviews related to the service provider using the related name 'to_review'
        reviews = obj.user.to_review.all()
        if reviews.exists():
            total_rating = sum(review.rating for review in reviews)
            return total_rating / reviews.count()  # Calculate the average rating
        return None  # Return None if no reviews are present   
      

# For detailed view of service provider        
class CustomerReviewSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomerReview
        fields = ['customer', 'rating', 'image', 'comment', 'created_at']

class ServiceRegisterSerializer(serializers.ModelSerializer):
    subcategory = serializers.CharField(source='subcategory.title')  # Use source to get the title instead of id

    class Meta:
        model = ServiceRegister
        fields = ['subcategory', 'image']  # Only include the field you want to display (e.g., subcategory.title)

class ServiceProviderProfileSerializer(serializers.ModelSerializer):
    full_name = serializers.CharField(source='user.full_name')
    address = serializers.CharField(source='user.address')
    landmark = serializers.CharField(source='user.landmark')
    pin_code = serializers.CharField(source='user.pin_code')
    district = serializers.CharField(source='user.district')
    state = serializers.CharField(source='user.state')
    about = serializers.CharField()
    work_history_completed = serializers.SerializerMethodField()  
    services = ServiceRegisterSerializer(many=True, read_only=True)  # Use the custom service serializer  
    reviews = CustomerReviewSerializer(many=True, source='user.to_review')  

    class Meta:
        model = ServiceProvider
        fields = ['full_name', 'address', 'landmark', 'pin_code', 'district', 'state', 'about','work_history_completed','services', 'reviews' ]

    def get_work_history_completed(self, obj):
        return ServiceRequest.objects.filter(service_provider=obj.user, work_status='completed').count()        
    


#for service request and request views
class ServiceRequestSerializer(serializers.ModelSerializer):
    subcategory_title = serializers.CharField(source='service.subcategory.title', read_only=True)
    subcategory_id = serializers.IntegerField(source='service.subcategory.id', read_only=True)  # Get subcategory ID
    #service_title = serializers.CharField(source='service.title', read_only=True)  # Get service title
    customer_name = serializers.CharField(source='customer.full_name', read_only=True)
    service_provider_name = serializers.CharField(source='service_provider.full_name', read_only=True)

    class Meta:
        model = ServiceRequest
        fields = [
            'customer_name',
            'service_provider_name',
            'service',  # Holds the service ID
            'title',  # Service title for output
            'subcategory_title',
            'subcategory_id',  # Subcategory ID for output
            'work_status',
            'acceptance_status',
            'availability_from',
            'availability_to',
            'additional_notes',
            'image',
            'booking_id',
           
        ]
        read_only_fields = ['booking_id', 'customer', 'service', 'title', 'subcategory_title', 'subcategory_id']

class ServiceRequestDetailSerializer(serializers.ModelSerializer):
    subcategory_name = serializers.CharField(source='service.subcategory.title', read_only=True)
    #service_title = serializers.CharField(source='service.title', read_only=True)  # Get service title
    customer_name = serializers.CharField(source='customer.full_name', read_only=True)

    class Meta:
        model = ServiceRequest
        fields = [
            'title',
            'subcategory_name',
            'customer_name',
            'availability_from',
            'availability_to',
            'acceptance_status'
        ]    

#invoice serializer
class InvoiceSerializer(serializers.ModelSerializer):
    total_amount = serializers.DecimalField(max_digits=10, decimal_places=2, read_only=True)  # Ensure total_amount is read-only

    class Meta:
        model = Invoice
        fields = [
            'invoice_number', 'invoice_type', 'service_request', 'sender', 
            'receiver', 'quantity', 'price', 'total_amount', 'payment_status','payment_balance',
            'invoice_date', 'due_date', 'appointment_date', 'additional_requirements',
            'accepted_terms'
        ]

#ongoing works
class ServiceRequestWithInvoiceSerializer(serializers.ModelSerializer):
    total_amount = serializers.DecimalField(source='invoices.first.total_amount', max_digits=10, decimal_places=2)
    appointment_date = serializers.DateTimeField(source='invoices.first.appointment_date')

    class Meta:
        model = ServiceRequest
        fields = ['id', 'service_provider', 'service', 'work_status', 'total_amount', 'appointment_date']

#completed works
class CompletedServiceRequestWithReviewSerializer(serializers.ModelSerializer):
    review_rating = serializers.SerializerMethodField()

    class Meta:
        model = ServiceRequest
        fields = ['id', 'service_provider', 'service', 'work_status', 'review_rating']

    def get_review_rating(self, obj):
        # Use getattr to safely access the related review
        review = getattr(obj, 'review', None)  # Access the reverse relationship
        if review and review.rating:
            return review.rating
        return None
    

#customer complaint
class ComplaintSerializer(serializers.ModelSerializer):
    service_request = serializers.CharField(source='service_request.booking_id')
    class Meta:
        model = Complaint
        fields = [
            'id', 'sender', 'receiver', 'service_request', 'subject',
            'description', 'images', 'submitted_at', 'status', 
            'resolved_at', 'resolution_notes'
        ]
        read_only_fields = ['sender', 'receiver', 'submitted_at', 'status', 'resolved_at', 'resolution_notes']

#customer review
class CustomerReviewSerializer(serializers.ModelSerializer):
    service_request = serializers.CharField(source='service_request.booking_id',read_only=True)
    customer = serializers.CharField(source='customer.username', read_only=True)
    service_provider = serializers.CharField(source='service_provider.username', read_only=True)

    class Meta:
        model = CustomerReview
        fields = ['id', 'rating', 'image', 'comment', 'created_at', 'service_request', 'customer', 'service_provider']

#transaction details
class PaymentSerializer(serializers.ModelSerializer):
    service_request = serializers.SerializerMethodField()
    class Meta:
        model = Payment
        fields = [
        'invoice',
        'sender',
        'receiver',
        'service_request',
        'transaction_id',
        'amount_paid',
        'payment_method',
        'payment_date',
        'payment_status',        
        ]

    def get_service_request(self, obj):
        # Check if the related invoice and service_request exist
        if obj.invoice and hasattr(obj.invoice, 'service_request'):
            return obj.invoice.service_request.title
        return None    