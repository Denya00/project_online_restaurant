from sqlalchemy import create_engine, String, Float, Integer, ForeignKey, Boolean, Text, DateTime, func
from sqlalchemy.orm import Mapped, mapped_column, relationship, sessionmaker
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy.dialects.postgresql import JSONB
from datetime import datetime
from flask_login import UserMixin
import os
import bcrypt

DATABASE_URL = os.environ.get("DATABASE_URL")

if not DATABASE_URL:
    PGUSER = "postgres"
    PGPASSWORD = "731025"
    DATABASE_URL = f"postgresql+psycopg2://{PGUSER}:{PGPASSWORD}@localhost:5432/online_restaurant"

engine = create_engine(DATABASE_URL, echo=True)
Session = sessionmaker(bind=engine)


class Base(DeclarativeBase):
    def create_db(self):
        Base.metadata.create_all(engine)

    def drop_db(self):
        Base.metadata.drop_all(engine)

class Users(Base, UserMixin):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True)
    nickname : Mapped[str] = mapped_column(String(100), unique=True)
    password : Mapped[str] = mapped_column(String(200))
    email : Mapped[str] = mapped_column(String(50), unique=True)

    reservations = relationship("Reservation", foreign_keys="Reservation.user_id" ,back_populates="user")
    orders = relationship("Orders", foreign_keys="Orders.user_id", back_populates='user')

    def set_password(self, password: str):
        self.password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    def check_password(self, password: str):
        return bcrypt.checkpw(password.encode('utf-8'), self.password.encode('utf-8'))

class Menu(Base):
    __tablename__ = "menu"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String)
    weight: Mapped[str] = mapped_column(String)
    ingredients : Mapped[str] = mapped_column(String)
    description: Mapped[str] = mapped_column(String)
    price: Mapped[int] = mapped_column()
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    file_name: Mapped[str] = mapped_column(String)

class Reservation(Base):
    __tablename__ = "reservation"
    id: Mapped[int] = mapped_column(primary_key=True)
    time_start: Mapped[datetime] = mapped_column(DateTime)
    type_table: Mapped[str] = mapped_column(String(20))
    user_id : Mapped[int] = mapped_column(ForeignKey('users.id'))

    user = relationship("Users", foreign_keys="Reservation.user_id" ,back_populates="reservations")

class Orders(Base):
    __tablename__ = "orders"
    id: Mapped[int] = mapped_column(primary_key=True)
    order_list: Mapped[dict] = mapped_column(JSONB)
    order_time: Mapped[datetime] = mapped_column(DateTime)
    user_id: Mapped[int] = mapped_column(ForeignKey('users.id'))

    user = relationship("Users", foreign_keys="Orders.user_id", back_populates="orders")

class Position(Base):
    __tablename__ = "position"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(100))
    weight: Mapped[str] = mapped_column(String(20))
    ingredients: Mapped[str] = mapped_column(Text)
    description: Mapped[str] = mapped_column(Text)
    price: Mapped[float] = mapped_column(Float)
    file_name: Mapped[str] = mapped_column(String(100))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

class AdminMessage(Base):
    __tablename__ = "admin_messages"

    id: Mapped[int] = mapped_column(primary_key=True)
    message: Mapped[str] = mapped_column(Text)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"))  

    user = relationship("Users")
