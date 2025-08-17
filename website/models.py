from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime
from . import db
# models.py
class CourseModule(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    order = db.Column(db.Integer, default=0)
    course_id = db.Column(db.Integer, db.ForeignKey('course.id'), nullable=False)
    
    # Relationships
    topics = db.relationship('ModuleTopic', backref='module', lazy=True, cascade="all, delete-orphan")
    
class ModuleTopic(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    order = db.Column(db.Integer, default=0)
    module_id = db.Column(db.Integer, db.ForeignKey('course_module.id'), nullable=False)
    
    # Relationships
    lessons = db.relationship('TopicLesson', backref='topic', lazy=True, cascade="all, delete-orphan")
    
class TopicLesson(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text)
    video_url = db.Column(db.String(500))
    video_file = db.Column(db.String(500))  # Path to uploaded video file
    image_file = db.Column(db.String(500))  # Path to uploaded image file
    order = db.Column(db.Integer, default=0)
    is_lab = db.Column(db.Boolean, default=False)
    topic_id = db.Column(db.Integer, db.ForeignKey('module_topic.id'), nullable=False)
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False, unique=True)
    password = db.Column(db.String(150), nullable=False)
    first_name = db.Column(db.String(150), nullable=False)
    last_name = db.Column(db.String(150), nullable=False)
    DOB = db.Column(db.Date, nullable=False)
    user_type = db.Column(db.String(50), nullable=False)
    has_paid = db.Column(db.Boolean, default=False)
    student_level = db.Column(db.String(50), nullable=True)  # Add this line
    
    # Relationships
    courses_taught = db.relationship('Course', backref='teacher', lazy=True)
    enrollments = db.relationship('Enrollment', backref='user', lazy=True)
    requests = db.relationship('Request', backref='user', lazy=True)
    discussions = db.relationship('Discussion', backref='user', lazy=True)
    replies = db.relationship('Reply', backref='user', lazy=True)
    quiz_submissions = db.relationship('QuizSubmission', backref='student', lazy=True)
    essay_submissions = db.relationship('EssaySubmission', backref='student', lazy=True)
    notifications_created = db.relationship('Notification', foreign_keys='Notification.created_by', backref='creator', lazy=True)
    library_resources = db.relationship('LibraryResource', foreign_keys='LibraryResource.uploaded_by', backref='uploader', lazy=True)
class Course(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    course_code = db.Column(db.String(20), nullable=False)
    course_name = db.Column(db.String(200), nullable=False)
    course_desc = db.Column(db.Text, nullable=False)
    course_limit = db.Column(db.Integer, nullable=False)
    teacher_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    resources = db.Column(db.String(500))
    resource_link = db.Column(db.String(500))
    target_level = db.Column(db.String(50))
    
    # Relationships
    enrollments = db.relationship('Enrollment', backref='course', lazy=True)
    requests = db.relationship('Request', backref='course', lazy=True)
    quizzes = db.relationship('Quiz', backref='course', lazy=True)
    essays = db.relationship('Essay', backref='course', lazy=True)
    discussions = db.relationship('Discussion', backref='course', lazy=True)
    live_lessons = db.relationship('LiveLesson', backref='course', lazy=True)

class Request(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    course_id = db.Column(db.Integer, db.ForeignKey('course.id'), nullable=False)
    status = db.Column(db.String(20), default='pending')

class Enrollment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    course_id = db.Column(db.Integer, db.ForeignKey('course.id'), nullable=False)

class Quiz(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    quiz_name = db.Column(db.String(200), nullable=False)
    course_id = db.Column(db.Integer, db.ForeignKey('course.id'), nullable=False)
    
    # Relationships
    questions = db.relationship('QuizQuestion', backref='quiz', lazy=True)
    submissions = db.relationship('QuizSubmission', backref='quiz', lazy=True)

class Essay(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    essay_name = db.Column(db.String(200), nullable=False)
    course_id = db.Column(db.Integer, db.ForeignKey('course.id'), nullable=False)
    
    # Relationships
    questions = db.relationship('EssayQuestion', backref='essay', lazy=True)
    submissions = db.relationship('EssaySubmission', backref='essay', lazy=True)

class QuizQuestion(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    question_text = db.Column(db.Text, nullable=False)
    quiz_id = db.Column(db.Integer, db.ForeignKey('quiz.id'), nullable=False)
    option1 = db.Column(db.String(200))
    option2 = db.Column(db.String(200))
    option3 = db.Column(db.String(200))
    max_grade = db.Column(db.Integer)
    
    # Relationships
    submissions = db.relationship('QuizSubmission', backref='question', lazy=True)

class EssayQuestion(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    essay_id = db.Column(db.Integer, db.ForeignKey('essay.id'), nullable=False)
    question_type = db.Column(db.String(50), nullable=False)
    file_upload = db.Column(db.LargeBinary)
    question_text = db.Column(db.Text)
    max_grade = db.Column(db.Integer)
    
    # Relationships
    submissions = db.relationship('EssaySubmission', backref='question', lazy=True)

class QuizSubmission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    selected_option = db.Column(db.String(200))
    quiz_id = db.Column(db.Integer, db.ForeignKey('quiz.id'), nullable=False)
    quizQuestion_id = db.Column(db.Integer, db.ForeignKey('quiz_question.id'), nullable=False)
    student_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    given_grade = db.Column(db.Integer)

class EssaySubmission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    answer_text = db.Column(db.Text)
    answer_file = db.Column(db.LargeBinary)
    answer_type = db.Column(db.String(50), nullable=False)
    essay_id = db.Column(db.Integer, db.ForeignKey('essay.id'), nullable=False)
    essayQuestion_id = db.Column(db.Integer, db.ForeignKey('essay_question.id'), nullable=False)
    student_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    given_grade = db.Column(db.Integer)

class Discussion(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False)
    course_id = db.Column(db.Integer, db.ForeignKey('course.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
    # Relationships
    replies = db.relationship('Reply', backref='discussion', lazy=True)

class Reply(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    discussion_id = db.Column(db.Integer, db.ForeignKey('discussion.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class LiveLesson(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    course_id = db.Column(db.Integer, db.ForeignKey('course.id'), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    stream_url = db.Column(db.String(500))
    is_active = db.Column(db.Boolean, default=False)

class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    message = db.Column(db.Text, nullable=False)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_visible = db.Column(db.Boolean, default=True)

class LibraryResource(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    type = db.Column(db.String(50), nullable=False)  # e.g., E-Book, Research Paper, etc.
    category = db.Column(db.String(50), nullable=False)  # e.g., Biology, Genetics, etc.
    author = db.Column(db.String(100), nullable=False)
    file_path = db.Column(db.String(500), nullable=False)  # path to the uploaded file
    file_name = db.Column(db.String(200), nullable=False)  # original file name
    file_size = db.Column(db.Integer, nullable=False)  # in bytes
    date_added = db.Column(db.DateTime, default=datetime.utcnow)
    uploaded_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    rating = db.Column(db.Float, default=0.0)
    downloads = db.Column(db.Integer, default=0)
    ai_summary = db.Column(db.Text)
    tags = db.Column(db.Text)  # Store tags as comma-separated string