-- הגדרת טבלאות
CREATE TABLE Users (
	UserID int IDENTITY PRIMARY KEY NOT NULL,
	FirstName nvarchar(30) NOT NULL,
	LastName nvarchar(30) NOT NULL,
	Username nvarchar(30) NOT NULL,
	Email nvarchar(120) NOT NULL,
	PasswordHash varbinary(max) NOT NULL,
	PasswordSalt nvarchar(100) NOT NULL
)
GO

CREATE TABLE Countries
(
CountryCode int IDENTITY PRIMARY KEY NOT NULL,
CountryName nvarchar(50) NOT NULL
)
GO

CREATE TABLE Categories
(
CategoryCode int IDENTITY PRIMARY KEY NOT NULL,
CategoryName nvarchar(100) NOT NULL
)
GO

CREATE TABLE SubCategories
(
SubCategoryCode int IDENTITY PRIMARY KEY NOT NULL,
CategoryCode int FOREIGN KEY REFERENCES Categories (CategoryCode) NOT NULL,
SubCategoryName nvarchar(100) NOT NULL
)
GO

CREATE TABLE Conditions
(
ConditionCode int IDENTITY PRIMARY KEY NOT NULL,
ConditionName nvarchar(30) NOT NULL
)
GO

CREATE TABLE SellTypes
(
SellTypeCode int IDENTITY PRIMARY KEY NOT NULL,
SellTypeName nvarchar(30) NOT NULL
)
GO

CREATE TABLE OrderStatus
(
OrderStatusID int IDENTITY PRIMARY KEY NOT NULL,
OrderStatusName nvarchar(30) NOT NULL
)
GO

CREATE TABLE UserAddresses
(
AddressID int IDENTITY PRIMARY KEY NOT NULL,
UserID int FOREIGN KEY REFERENCES Users (UserID) NOT NULL,
FirstName nvarchar(30) NOT NULL,
LastName nvarchar(30) NOT NULL,
AddressLine1 nvarchar(100) NOT NULL,
AddressLine2 nvarchar(100),
City nvarchar(60) NOT NULL,
CountryCode int FOREIGN KEY REFERENCES Countries (CountryCode) NOT NULL,
ZipCode nvarchar(20),
PhoneNumber nvarchar(20)
)
GO

CREATE TABLE ShipsToTypes
(
ShipsToTypeCode int IDENTITY PRIMARY KEY,
ShipsToTypeName nvarchar(30)
)
GO

CREATE TABLE Products
(
ProductID int IDENTITY PRIMARY KEY NOT NULL,
UserID int FOREIGN KEY REFERENCES Users (UserID) NOT NULL,
CategoryCode int FOREIGN KEY REFERENCES Categories (CategoryCode),
SubCategoryCode int FOREIGN KEY REFERENCES SubCategories (SubCategoryCode),
ConditionCode int FOREIGN KEY REFERENCES Conditions (ConditionCode) NOT NULL,
ProductName nvarchar(80) NOT NULL,
Price float,
SellTypeCode int FOREIGN KEY REFERENCES SellTypes (SellTypeCode) NOT NULL,
CountryCode int FOREIGN KEY REFERENCES Countries (CountryCode),
ShipsToTypeCode int FOREIGN KEY REFERENCES ShipsToTypes (ShipsToTypeCode) NOT NULL,
ShippingCosts float,
Description nvarchar(400),
Quantity int NOT NULL,
Size nvarchar(50),
UploadDate datetime NOT NULL,
ImagesSource nvarchar(100),
IsHidden bit NOT NULL
)
GO

CREATE TABLE Cart
(
CartID int FOREIGN KEY REFERENCES Users (UserID) NOT NULL,
ProductID int FOREIGN KEY REFERENCES Products (ProductID) NOT NULL
)
GO

CREATE TABLE Orders
(
OrderID int IDENTITY PRIMARY KEY NOT NULL,
UserID int FOREIGN KEY REFERENCES Users (UserID) NOT NULL,
FirstName nvarchar(30) NOT NULL,
LastName nvarchar(30) NOT NULL,
AddressLine1 nvarchar(100) NOT NULL,
AddressLine2 nvarchar(100),
City nvarchar(60) NOT NULL,
CountryCode int FOREIGN KEY REFERENCES Countries (CountryCode) NOT NULL,
ZipCode nvarchar(20),
PhoneNumber nvarchar(20),
Total float,
CreatedOn datetime NOT NULL
)
GO

CREATE TABLE OrderItems
(
OrderID int FOREIGN KEY REFERENCES Orders (OrderID) NOT NULL,
ProductID int FOREIGN KEY REFERENCES Products (ProductID) NOT NULL,
OrderStatusID int FOREIGN KEY REFERENCES OrderStatus (OrderStatusID)
)
GO

CREATE TABLE Chats
(
ChatID int IDENTITY PRIMARY KEY,
UserOneID int FOREIGN KEY REFERENCES Users (UserID),
UserTwoID int FOREIGN KEY REFERENCES Users (UserID),
Subject nvarchar(80),
CreatedOn datetime,
LastReplySentOn datetime
)
GO

CREATE TABLE Replies
(
UserID int FOREIGN KEY REFERENCES Users (UserID),
ChatID int FOREIGN KEY REFERENCES Chats (ChatID),
Reply nvarchar(200),
TimeSent datetime
)
GO


--יצירת פרוצדורות

Set DateFormat dmy
GO


-- הצפנת סיסמא
CREATE PROC HashPass(@pass nvarchar(255), @out varbinary(max) output)
AS
SET @out = HASHBYTES('SHA2_512', @pass)
GO



CREATE PROC DoesEmailExists
(@Email nvarchar(120))
AS
BEGIN
	IF EXISTS(SELECT * FROM Users WHERE Email = @Email)
	BEGIN
		SELECT 'true'
	END
	ELSE
	BEGIN
		SELECT 'false'
	END
END
GO

CREATE PROC IsUsernameExists
(@Username nvarchar(120))
AS
BEGIN
	IF EXISTS(SELECT * FROM Users WHERE Username = @Username)
	BEGIN
		SELECT 'true'
	END
	ELSE
	BEGIN
		SELECT 'false'
	END
END
GO


-- הוספת משתמש
CREATE PROC AddUser(
@FirstName nvarchar(30),
@LastName nvarchar(30),
@Username nvarchar(30),
@Email nvarchar(120),
@Password nvarchar(30)
)
AS
BEGIN TRANSACTION
DECLARE @Salt varchar(100)
SET @Salt = CONVERT(varchar(100), NEWID())
DECLARE @PassConcat nvarchar(255)
SET @PassConcat = CONCAT(@Password, @Salt)
DECLARE @PasswordHash varbinary(max)
EXEC HashPass @PassConcat, @PasswordHash OUTPUT
INSERT Users(FirstName, LastName, Username, Email, PasswordHash, PasswordSalt)
VALUES (@FirstName, @LastName, @Username, @Email, @PasswordHash, @Salt)
IF @@ERROR<>0
BEGIN
	ROLLBACK TRANSACTION
	PRINT(@@ERROR)
	RETURN
END
COMMIT TRANSACTION
GO


-- קבלת סיסמא מוצפנת
CREATE PROC GetHash (
@Password nvarchar(30),
@PasswordSalt nvarchar(100),
@Result varbinary(max) OUTPUT
)
AS
SELECT @Result = HASHBYTES('SHA2_512', CONCAT(@Password, @PasswordSalt))
GO


-- אימות משתמש
CREATE PROC ValidateUser
(
@Email nvarchar(120),
@Password nvarchar(130),
@Result int OUTPUT
)
AS
DECLARE @PassSalt nvarchar(100)
SELECT @PassSalt = PasswordSalt FROM Users WHERE Email = @Email
DECLARE @PassHash varbinary(max)
EXEC GetHash @Password, @PassSalt, @PassHash OUTPUT  -- מקבל את ההצפנה של הסיסמא שהתבקלה
IF ((SELECT PasswordHash FROM Users WHERE Email = @Email) = @PassHash)
BEGIN
SELECT @Result = UserID FROM Users WHERE Email = @Email AND PasswordHash = @PassHash
END
ELSE
BEGIN
SET @Result = 0
END
GO


--ID הצגת משתמש לפי
CREATE PROC GetUserById(@UserID int)
AS
SELECT * FROM Users WHERE UserID = @UserID
GO

CREATE PROC GetUsernameById
(
@UserID int
)
AS
SELECT Username FROM Users
WHERE UserID = @UserID
GO

EXEC GetUsernameById 1
GO

CREATE PROC ChangeUsername
(
@UserID int,
@Username nvarchar(30)
)
AS
BEGIN TRANSACTION
UPDATE Users
SET Username = @Username
WHERE UserID = @UserID
IF @@ERROR<>0
BEGIN
	ROLLBACK TRANSACTION
	PRINT(@@ERROR)
	RETURN
END
COMMIT TRANSACTION
GO


CREATE PROC ChangeEmail
(
@UserID int,
@Email nvarchar(120)
)
AS
BEGIN TRANSACTION
UPDATE Users
SET Email = @Email
WHERE UserID = @UserID
IF @@ERROR<>0
BEGIN
	ROLLBACK TRANSACTION
	PRINT(@@ERROR)
	RETURN
END
COMMIT TRANSACTION
GO

--עדכון פרטי משתמש
CREATE PROC EditUserInfo
(
@UserID int,
@FirstName nvarchar(30),
@LastName nvarchar(30),
@Username nvarchar(30),
@Email nvarchar(120)
)
AS
BEGIN TRANSACTION
UPDATE Users
SET FirstName = @FirstName, 
LastName = @LastName,
Username = @Username,
Email = @Email
WHERE UserID = @UserID
IF @@ERROR<>0
BEGIN
	ROLLBACK TRANSACTION
	PRINT(@@ERROR)
	RETURN
END
COMMIT TRANSACTION
GO


CREATE PROC IsCurrentPasswordTheSame
(
@UserID int,
@Password nvarchar(16)
)
AS
BEGIN TRANSACTION
DECLARE @PassSalt nvarchar(100)
SELECT @PassSalt = PasswordSalt FROM Users WHERE UserID = @UserID
DECLARE @PassHash varbinary(max)
EXEC GetHash @Password, @PassSalt, @PassHash OUTPUT
IF ((SELECT PasswordHash FROM Users WHERE UserID = @UserID) = @PassHash)
BEGIN
SELECT 'true'
END
ELSE
BEGIN
SELECT 'false'
END
IF @@ERROR<>0
BEGIN
	ROLLBACK TRANSACTION
	PRINT(@@ERROR)
	RETURN
END
COMMIT TRANSACTION
GO

-- מחזיר את המזהה של המשתמש לפי האימייל
CREATE PROC GetUserIDByEmail
(
@Email nvarchar(120)
)
AS
SELECT UserID FROM Users WHERE Email=@Email
GO

EXEC GetUserIDByEmail 'nivohayon1582@gmail.com'

CREATE PROC ChangePassword
(
@UserID int,
@Password nvarchar(16)
)
AS
BEGIN TRANSACTION
DECLARE @PassSalt nvarchar(100)
SELECT @PassSalt = PasswordSalt FROM Users WHERE UserID = @UserID
DECLARE @PassHash varbinary(max)
EXEC GetHash @Password, @PassSalt, @PassHash OUTPUT
UPDATE Users
SET PasswordHash = @PassHash
WHERE UserID = @UserID
IF @@ERROR<>0
BEGIN
	ROLLBACK TRANSACTION
	PRINT(@@ERROR)
	RETURN
END
COMMIT TRANSACTION
GO


--יצירת צאט
CREATE PROC CreateChat
(
@UserOneID int,
@UserTwoID int,
@Subject nvarchar(80)
)
AS
BEGIN TRANSACTION
IF EXISTS(SELECT ChatID FROM Chats WHERE UserOneID = @UserOneID AND UserTwoID = @UserTwoID)
BEGIN
SELECT 0
END
ELSE BEGIN
INSERT Chats(UserOneID, UserTwoID, Subject, CreatedOn) 
VALUES (@UserOneID, @UserTwoID, @Subject, GETDATE())
END
IF @@ERROR<>0
BEGIN
	ROLLBACK TRANSACTION
	PRINT(@@ERROR)
	RETURN
END
COMMIT TRANSACTION
GO


--מחיקת צאט
CREATE PROC DeleteChat
(
@ChatID int
)
AS
BEGIN TRANSACTION
DELETE FROM Replies WHERE ChatID = @ChatID
DELETE FROM Chats WHERE ChatID = @ChatID
IF @@ERROR<>0
BEGIN
	ROLLBACK TRANSACTION
	PRINT(@@ERROR)
	RETURN
END
COMMIT TRANSACTION
GO


--שליחת הודעה
CREATE PROC SendMessage
(
@UserID int,
@ChatID int,
@Reply nvarchar(200)
)
AS
BEGIN TRANSACTION
INSERT Replies(UserID, ChatID, Reply, TimeSent)
VALUES (@UserID, @ChatID, @Reply, GETDATE())
IF @@ERROR<>0
BEGIN
	ROLLBACK TRANSACTION
	PRINT(@@ERROR)
	RETURN
END
COMMIT TRANSACTION
GO

CREATE PROC GetAllChatsByUserID
(
@UserID int
)
AS
BEGIN TRANSACTION
SELECT * FROM Chats WHERE UserOneID = @UserID OR UserTwoID = @UserID
IF @@ERROR<>0
BEGIN
	ROLLBACK TRANSACTION
	PRINT(@@ERROR)
	RETURN
END
COMMIT TRANSACTION
GO

-- מחזיר את כל ההודעות בצאט
CREATE PROC GetAllRepliesByChatID
(
@ChatID int
)
AS
BEGIN TRANSACTION
SELECT * FROM Replies WHERE ChatID = @ChatID
IF @@ERROR<>0
BEGIN
	ROLLBACK TRANSACTION
	PRINT(@@ERROR)
	RETURN
END
COMMIT TRANSACTION
GO


-- בודק אם קיים צאט כבר
-- UserOneID - Buyer.
-- UserTwoID - Seller.
CREATE PROC DoesChatExists
(
@ChatID int,
@UserOneID int,
@UserTwoID int
)
AS
BEGIN TRANSACTION
SELECT ChatID FROM Chats WHERE ChatID = @ChatID AND (UserOneID = @UserOneID AND UserTwoID = @UserTwoID)
IF @@ERROR<>0
BEGIN
	ROLLBACK TRANSACTION
	PRINT(@@ERROR)
	RETURN
END
COMMIT TRANSACTION
GO

EXEC GetChatID 2,1

CREATE PROC GetChatID
(
@UserOneID int,
@UserTwoID int
)
AS
BEGIN TRANSACTION
IF EXISTS(SELECT ChatID FROM Chats WHERE UserOneID = @UserOneID AND UserTwoID = @UserTwoID)
BEGIN
	SELECT ChatID FROM Chats WHERE UserOneID = @UserOneID AND UserTwoID = @UserTwoID
END
ELSE BEGIN
	SELECT -1
END
IF @@ERROR<>0
BEGIN
	ROLLBACK TRANSACTION
	PRINT(@@ERROR)
	RETURN
END
COMMIT TRANSACTION
GO


--הוספת כתובת למשתמש
CREATE PROC AddAddress
(
@UserID int,
@FirstName nvarchar(30),
@LastName nvarchar(30),
@AddressLine1 nvarchar(100),
@AddressLine2 nvarchar(100),
@City nvarchar(60),
@CountryCode int,
@ZipCode nvarchar(20),
@PhoneNumber nvarchar(20)
)
AS
BEGIN TRANSACTION
INSERT UserAddresses(UserID, FirstName, LastName, AddressLine1, AddressLine2, City, CountryCode, ZipCode, PhoneNumber)
VALUES (@UserID, @FirstName, @LastName, @AddressLine1, @AddressLine2, @City, @CountryCode, @ZipCode, @PhoneNumber)
IF @@ERROR<>0
BEGIN
	ROLLBACK TRANSACTION
	PRINT(@@ERROR)
	RETURN
END
COMMIT TRANSACTION
GO


--מחיקת כתובת
CREATE PROC DeleteAddress
(
@AddressID int
)
AS
BEGIN TRANSACTION
DELETE FROM UserAddresses WHERE AddressID = @AddressID
IF @@ERROR<>0
BEGIN
	ROLLBACK TRANSACTION
	PRINT(@@ERROR)
	RETURN
END
COMMIT TRANSACTION
GO


-- AddressID הצגת כתובת לפי
CREATE PROC GetAddressById
(
@AddressID int
)
AS
SELECT * FROM UserAddresses WHERE AddressID = @AddressID
GO


-- UserID הצגת כתובות לפי
CREATE PROC GetAddressesByUserId
(
@UserID int
)
AS
SELECT * FROM UserAddresses WHERE UserID = @UserID
GO

--עדכון פרטי כתובת
CREATE PROC EditAddress
(
@AddressID int,
@FirstName nvarchar(30),
@LastName nvarchar(30),
@AddressLine1 nvarchar(100),
@AddressLine2 nvarchar(100),
@City nvarchar(60),
@CountryCode int,
@ZipCode nvarchar(20),
@PhoneNumber nvarchar(20)
)
AS
BEGIN TRANSACTION
UPDATE UserAddresses
SET FirstName = @FirstName, 
LastName = @LastName,
AddressLine1 = @AddressLine1,
AddressLine2 = @AddressLine2,
City = @City,
CountryCode = @CountryCode,
ZipCode = @ZipCode,
PhoneNumber = @PhoneNumber
WHERE AddressID = @AddressID
IF @@ERROR<>0
BEGIN
	ROLLBACK TRANSACTION
	PRINT(@@ERROR)
	RETURN
END
COMMIT TRANSACTION
GO


-- הוספת מוצר
CREATE PROC AddProduct
(
@UserID int,
@CategoryCode int,
@SubCategoryCode int,
@ConditionCode int,
@ProductName nvarchar(80),
@Price float,
@SellTypeCode int,
@CountryCode int,
@ShipsToTypeCode int,
@ShippingCosts float,
@Description nvarchar(400),
@Quantity int,
@Size nvarchar(50),
@ImagesSource nvarchar(100)
)
AS
BEGIN TRANSACTION
INSERT Products(UserID, CategoryCode, SubCategoryCode, ConditionCode, ProductName, Price, SellTypeCode, CountryCode, ShipsToTypeCode, ShippingCosts, Description, Quantity, Size, UploadDate, ImagesSource, IsHidden)
VALUES (@UserID, @CategoryCode, @SubCategoryCode, @ConditionCode, @ProductName, @Price, @SellTypeCode, @CountryCode, @ShipsToTypeCode, @ShippingCosts, @Description, @Quantity, @Size, GETDATE(), @ImagesSource, 0)
DECLARE @IdentityCode int
SET @IdentityCode = SCOPE_IDENTITY()
COMMIT TRANSACTION
RETURN @IdentityCode
IF @@ERROR<>0
BEGIN
	ROLLBACK TRANSACTION
	PRINT(@@ERROR)
	RETURN
END
COMMIT TRANSACTION
GO

-- ערוך מוצר
CREATE PROC EditProduct
(
@ProductID int,
@CategoryCode int,
@SubCategoryCode int,
@ConditionCode int,
@ProductName nvarchar(80),
@Price float,
@SellTypeCode int,
@CountryCode int,
@ShipsToTypeCode int,
@ShippingCosts float,
@Description nvarchar(400),
@Quantity int,
@Size nvarchar(50),
@ImagesSource nvarchar(100)
)
AS
BEGIN TRANSACTION
UPDATE Products SET CategoryCode = @CategoryCode,
SubCategoryCode = @SubCategoryCode,
ConditionCode = @ConditionCode,
ProductName = @ProductName,
Price = @Price,
SellTypeCode = @SellTypeCode,
CountryCode = @CountryCode,
ShipsToTypeCode = @ShipsToTypeCode,
ShippingCosts = @ShippingCosts,
Description = @Description,
Quantity = @Quantity,
Size = @Size,
UploadDate = GETDATE(),
ImagesSource = @ImagesSource
WHERE ProductID = @ProductID
COMMIT TRANSACTION
IF @@ERROR<>0
BEGIN
	ROLLBACK TRANSACTION
	PRINT(@@ERROR)
	RETURN
END
GO

-- עריכת מקור תמונות
CREATE PROC EditProductImagesSource(
@ProductID int,
@ImagesSource nvarchar(100)
)
AS
BEGIN TRANSACTION
UPDATE Products
SET ImagesSource = @ImagesSource
WHERE ProductID = @ProductID
IF @@ERROR<>0
BEGIN
	ROLLBACK TRANSACTION
	PRINT(@@ERROR)
	RETURN
END
COMMIT TRANSACTION
GO

-- מחיקת מוצר
CREATE PROC DeleteProduct
(
@ProductID int
)
AS
BEGIN TRANSACTION
UPDATE Products
SET IsHidden = 1
WHERE ProductID = @ProductID
IF @@ERROR<>0
BEGIN
	ROLLBACK TRANSACTION
	PRINT(@@ERROR)
	RETURN
END
COMMIT TRANSACTION
GO



--הוספת מוצר לעגלה
CREATE PROC AddToCart
(
@CartID int,
@ProductID int
)
AS
BEGIN TRANSACTION
IF ((SELECT COUNT(ProductID) FROM Cart WHERE CartID = @CartID AND ProductID = @ProductID) = 0)
BEGIN
	INSERT Cart(CartID, ProductID) VALUES (@CartID, @ProductID)
	IF @@ERROR<>0
	BEGIN
		ROLLBACK TRANSACTION
		PRINT(@@ERROR)
		RETURN
	END
END
COMMIT TRANSACTION
GO


--מחיקה מעגלה
CREATE PROC RemoveFromCart
(
@CartID int,
@ProductID int
)
AS
BEGIN TRANSACTION
DELETE FROM Cart WHERE CartID = @CartID AND ProductID = @ProductID
IF @@ERROR<>0
BEGIN
	ROLLBACK TRANSACTION
	PRINT(@@ERROR)
	RETURN
END
COMMIT TRANSACTION
GO


--ProductID הצגת מוצר לפי
CREATE PROC GetProductByProductID
(
@ProductID int
)
AS
BEGIN TRANSACTION
SELECT * FROM Products WHERE ProductID = @ProductID
IF @@ERROR<>0
BEGIN
	ROLLBACK TRANSACTION
	PRINT(@@ERROR)
	RETURN
END
COMMIT TRANSACTION
GO



--UserID הצגת מוצרים לפי
CREATE PROC GetCartItemsByUserID
(
@CartID int
)
AS
BEGIN TRANSACTION
SELECT Products.ProductID, UserID, CategoryCode, SubCategoryCode, ConditionCode,
ProductName, Price, SellTypeCode, CountryCode, ShipsToTypeCode,
ShippingCosts, Description, Quantity, Size, UploadDate,
ImagesSource, IsHidden FROM Products INNER JOIN Cart ON Cart.ProductID = Products.ProductID WHERE CartID = @CartID AND IsHidden = 0
IF @@ERROR<>0
BEGIN
	ROLLBACK TRANSACTION
	PRINT(@@ERROR)
	RETURN
END
COMMIT TRANSACTION
GO


--יצירת הזמנה
CREATE PROC MakeOrder
(
@UserID int,
@AddressID int
)
AS
BEGIN TRANSACTION
DECLARE @Total float
SET @Total = 0
DECLARE @FirstName nvarchar(30)
SELECT @FirstName = FirstName FROM UserAddresses WHERE AddressID = @AddressID
DECLARE @LastName nvarchar(30)
SELECT @LastName = LastName FROM UserAddresses WHERE AddressID = @AddressID
DECLARE @AddressLine1 nvarchar(100)
SELECT @AddressLine1 = AddressLine1 FROM UserAddresses WHERE AddressID = @AddressID
DECLARE @AddressLine2 nvarchar(100)
SELECT @AddressLine2 = AddressLine2 FROM UserAddresses WHERE AddressID = @AddressID
DECLARE @City nvarchar(60)
SELECT @City = City FROM UserAddresses WHERE AddressID = @AddressID
DECLARE @CountryCode int
SELECT @CountryCode = CountryCode FROM UserAddresses WHERE AddressID = @AddressID
DECLARE @ZipCode nvarchar(20)
SELECT @ZipCode = ZipCode FROM UserAddresses WHERE AddressID = @AddressID
DECLARE @PhoneNumber nvarchar(20)
SELECT @PhoneNumber = PhoneNumber FROM UserAddresses WHERE AddressID = @AddressID
INSERT Orders(UserID, FirstName, LastName, AddressLine1, AddressLine2, City, CountryCode, ZipCode, PhoneNumber, Total, CreatedOn)
VALUES (@UserID, @FirstName, @LastName, @AddressLine1, @AddressLine2, @City, @CountryCode, @ZipCode, @PhoneNumber, @Total, GETDATE())
IF @@ERROR<>0
BEGIN
	ROLLBACK TRANSACTION
	PRINT(@@ERROR)
	RETURN
END
COMMIT TRANSACTION
GO


--פונקציה שמחזירה את הסכום הסופי של ההזמנה
CREATE FUNCTION GetOrderItemsPriceSum(@OrderID int)
RETURNS float
AS
BEGIN
DECLARE @PriceSum float
SELECT @PriceSum = SUM(Price) FROM Orders
INNER JOIN OrderItems ON OrderItems.OrderID = Orders.OrderID
INNER JOIN Products ON Products.ProductID = OrderItems.ProductID
WHERE Orders.OrderID = @OrderID
DECLARE @ShippingCostsSum float
SELECT @ShippingCostsSum = SUM(ShippingCosts) FROM Orders
INNER JOIN OrderItems ON OrderItems.OrderID = Orders.OrderID
INNER JOIN Products ON Products.ProductID = OrderItems.ProductID
WHERE Orders.OrderID = @OrderID
RETURN @PriceSum + @ShippingCostsSum
END
GO


--הוספת מוצרים להזמנה
CREATE PROC AddItemsToOrder
(
@OrderID int,
@ProductID int
)
AS
BEGIN TRANSACTION
DECLARE @OrderStatusCode int
SET @OrderStatusCode = 1
INSERT OrderItems(OrderID, ProductID, OrderStatusID) VALUES (@OrderID, @ProductID, @OrderStatusCode)
IF @@ERROR<>0
BEGIN
	ROLLBACK TRANSACTION
	PRINT(@@ERROR)
	RETURN
END
COMMIT TRANSACTION
GO


--שינוי סטטוס הזמנה
CREATE PROC ChangeProductStatus
(
@OrderID int,
@ProductID int,
@OrderStatusCode int
)
AS
BEGIN TRANSACTION
UPDATE OrderItems
SET OrderStatusID = @OrderStatusCode
WHERE OrderID = @OrderID AND ProductID = @ProductID
IF @@ERROR<>0
BEGIN
	ROLLBACK TRANSACTION
	PRINT(@@ERROR)
	RETURN
END
COMMIT TRANSACTION
GO


--הצגת כל הקטגוריות
CREATE PROC GetAllCategories
AS
SELECT * FROM Categories
ORDER BY CategoryName
GO


--הצגת כל התתי קטגוריות
CREATE PROC GetAllSubCategories
AS
SELECT * FROM SubCategories
ORDER BY SubCategoryName
GO


--הצגת כל המוצרים
CREATE PROC GetAllProducts
AS
SELECT * FROM Products WHERE IsHidden = 0
GO


--הצגת כל המוצרים לפי קטגוריה
CREATE PROC GetProductsByCategory(@CategoryCode int)
AS
SELECT * FROM Products
WHERE CategoryCode = @CategoryCode
GO

--הצגת כל המוצרים לפי המשתמש שהעלה אותם
CREATE PROC GetUserProducts(@UserID int)
AS
SELECT * FROM Products
WHERE UserID = @UserID AND IsHidden = 0
GO

-- הצגת 5 המוצרים האחרונים שהועלו
CREATE PROC GetLatestProducts
AS
SELECT TOP 5 * FROM Products
WHERE IsHidden = 0
ORDER BY UploadDate DESC
GO

UPDATE Products SET IsHidden = 0

select * from Products

-- הוספת טריגרים
CREATE TRIGGER T_LastSentMessage
ON Replies FOR INSERT
AS
UPDATE Chats
SET LastReplySentOn = GETDATE()
FROM Replies INNER JOIN inserted
ON Replies.ChatID = inserted.ChatID
WHERE Chats.ChatID = inserted.ChatID
GO


-- הזנת נתונים לטבלאות לצורך בדיקות

EXEC AddUser 'Niv', 'Ohayon', 'nivohayon1582', 'nivohayon1582@gmail.com', '1582'
EXEC AddUser 'Erez', 'Sudai', 'ErezSudai420', 'erezdudai420@gmail.com', 'erezPass'
EXEC AddUser 'Katrin', 'Faerman', 'Katrin7', 'katrinf7@gmail.com', '7777'
EXEC AddUser 'Tommy', 'Pailles', 'ZeChoosenOne', 'tommypailles@gmail.com', '4321'
GO

SELECT * FROM Users
GO


EXEC SendMessage 1, 93, 'Hey Niv'
EXEC SendMessage 1, 93, 'Hey Erez How Are You?'
EXEC SendMessage 2, 93, 'I Am Fine Niv, Thank You'
EXEC SendMessage 2, 93, 'Can We Talk On The Phone Niv?'
EXEC SendMessage 1, 1, 'Yeah Sure Call Me Erez'
EXEC SendMessage 3, 2, 'Hey Tommy'
EXEC SendMessage 4, 2, 'Hey Katrin How Are You?'
EXEC SendMessage 3, 2, 'I Am Fine Tommy, Thank You'
EXEC SendMessage 3, 2, 'Can We Talk On The Phone Tommy?'
EXEC SendMessage 23, 3, 'Yeah Sure Call Me Katrin33333'
GO

SELECT * FROM Replies
GO

SELECT * FROM Chats
GO

DELETE FROM Chats WHERE ChatID >3
GO


EXEC DoesChatExists 1,2

EXEC GetAllRepliesByChatID 22
GO

SELECT * FROM Products


EXEC DeleteChat 475

SELECT Users.FirstName, Replies.Reply, Replies.TimeSent FROM Replies INNER JOIN Users ON
Users.UserID = Replies.UserID
WHERE ChatID = 2 AND Users.UserID = 23
ORDER BY TimeSent
GO

INSERT Categories(CategoryName) VALUES ('Computers')
INSERT Categories(CategoryName) VALUES ('Electronics')
INSERT Categories(CategoryName) VALUES ('Art')
INSERT Categories(CategoryName) VALUES ('Collectibles')
INSERT Categories(CategoryName) VALUES ('Home Decoration')
INSERT Categories(CategoryName) VALUES ('Garden')
INSERT Categories(CategoryName) VALUES ('Toys')
INSERT Categories(CategoryName) VALUES ('Jewelry')
GO

SELECT * FROM Categories
GO
--Computers
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (1, 'CPU')
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (1, 'GPU')
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (1, 'Power Supply')
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (1, 'Motherboard')
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (1, 'SSD')
GO
--Electronics
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (2, 'Cables')
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (2, 'Transistors')
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (2, 'Chips')
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (2, 'Led')
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (2, 'Relays')
GO
--Art
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (3, 'Pen')
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (3, 'Canvas')
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (3, 'Brush')
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (3, 'Water Colors')
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (3, 'Oil Colors')
GO
--Collectibles
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (4, 'Stamps')
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (4, 'Vintage Record Players')
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (4, 'Collectible Comics')
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (4, 'Vintage Clothings And Accessories')
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (4, 'Collectible Postcards')
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (4, 'Coins And Money')
INSERT SubCategories(CategoryCode, SubCategoryName) VALUES (4, 'Antiques')
GO

SELECT * FROM SubCategories
GO

SELECT Categories.CategoryName, SubCategories.SubCategoryName FROM SubCategories
INNER JOIN Categories ON Categories.CategoryCode = SubCategories.CategoryCode
GO

INSERT Conditions(ConditionName) VALUES ('New In The Box')
INSERT Conditions(ConditionName) VALUES ('Like New')
INSERT Conditions(ConditionName) VALUES ('Used')
INSERT Conditions(ConditionName) VALUES ('Require Fixing')
INSERT Conditions(ConditionName) VALUES ('Irrelevant')
GO

SELECT * FROM Conditions
GO

INSERT Countries(CountryName) VALUES ('Israel')
INSERT Countries(CountryName) VALUES ('Russia')
INSERT Countries(CountryName) VALUES ('Egypt')
INSERT Countries(CountryName) VALUES ('Greece')
INSERT Countries(CountryName) VALUES ('Belgium')
GO

SELECT * FROM Countries
GO

INSERT OrderStatus(OrderStatusName) VALUES ('Not Yet Shipped')
INSERT OrderStatus(OrderStatusName) VALUES ('Shipped')
INSERT OrderStatus(OrderStatusName) VALUES ('Recieved')
GO

DBCC CHECKIDENT ('Chats', RESEED, 4)
SELECT * FROM Orders
GO

INSERT SellTypes(SellTypeName) VALUES ('Buy Now')
INSERT SellTypes(SellTypeName) VALUES ('Auction')
GO

SELECT * FROM SellTypes
GO

EXEC AddAddress 1,'niv', 'ohayon', 'hahasda 4', 'apt 2', 'netanya', 1, '42753', '0525438583'
EXEC AddAddress 1,'niv1', 'ohayon1', 'hahasda 1', 'apt 21', 'netanya1', 1, '427531', '05254385831'
EXEC AddAddress 2,'erez', 'sudai', 'shalom shabzi', NULL, 'netanya', 1, '42753', '0525438583'
EXEC AddAddress 2,'erez1', 'sudai1', 'shalom shabzi 1', 'apt 1', 'netanya1', 1, 'a1212s1', '324634621'
EXEC AddAddress 3,'katrin', 'ohayon', 'nuefeld', 'apt 3', 'netanya', 1, '324512', '3463456344'
EXEC AddAddress 3,'katrin1', 'faerman1', 'nuefeld 1', NULL, 'netanya1', 1, '21341', '456734563'
EXEC AddAddress 4,'tommy', 'pailles', 'hator', NULL, 'netanya', 1, '34253', '67978057671'
EXEC AddAddress 4,'tommy1', 'pailles1', 'hator1', 'apt 8', 'netanya1', 1, '345345', '3452345637'
GO

SELECT * FROM UserAddresses
GO

EXEC EditAddress 11, 'nivni1v', 'ohayon12', 'katrin 1212', 'apt 2121', 'netanya1212', 2, 'j22bn', '0522342342'
GO


--EXEC DeleteAddress 4
--GO

INSERT ShipsToTypes(ShipsToTypeName) VALUES ('Worldwide')
INSERT ShipsToTypes(ShipsToTypeName) VALUES ('My Country Only')
INSERT ShipsToTypes(ShipsToTypeName) VALUES ('Contact Me')
GO

SELECT * FROM ShipsToTypes
GO

EXEC AddProduct 1, 1, 1, 1, 'Xbox 360 1 Year Old', 300, 1, 1, 1, 25.5, 'Works Smoothly Like New', 1, 'X-10cm Y-20cm Z-50cm ', NULL
EXEC AddProduct 1, 1, 2, 1, 'Xbox One 2 Years Old', 500, 1, 1, 1, 35, 'Works Like New Comes With 2 Controllers', 1, 'X-10cm Y-20cm Z-50cm ', NULL
EXEC AddProduct 2, 1, 3, 1, 'PS4 1 Year Old', 300, 1, 1, 1, 10.34, 'Works Smoothly Like New', 1, 'X-10cm Y-20cm Z-50cm ', NULL
EXEC AddProduct 2, 1, 4, 1, 'PS5 2 Years Old', 500, 1, 1, 1, 16.4, 'Works Smoothly Like New', 1, 'X-10cm Y-20cm Z-50cm ', NULL
EXEC AddProduct 3, 1, 2, 1, 'PC 1 Year Old', 200, 1, 1, 1, 8.78, 'Works Smoothly Like New', 1, 'X-10cm Y-20cm Z-50cm ', NULL
EXEC AddProduct 4, 1, 1, 1, 'Gaming PC 360 2 Year Old', 400, 1, 1, 1, 5.21, 'Works Smoothly Like New', 1, 'X-10cm Y-20cm Z-50cm ', NULL
GO

SELECT * FROM Products
WHERE IsHidden = 0
GO

EXEC EditProduct 36, 3, 13, 2, 'Inflating Pinguin Water', 69, 1, 3, 2, 5, 'Desc', 2, 'Size', '/Images/User24/Products/36/'

DBCC CHECKIDENT ('Chats', RESEED, 0) --Reset Identity Column To Start With 1.

SELECT * FROM Cart

DELETE FROM Users

SELECT * FROM Products

DELETE FROM Cart

EXEC GetLatestProducts
GO

EXEC AddToCart 1, 1
EXEC AddToCart 1, 3
EXEC AddToCart 1, 4
EXEC AddToCart 1, 5
EXEC AddToCart 2, 6
EXEC AddToCart 2, 2
EXEC AddToCart 2, 4
EXEC AddToCart 3, 2
EXEC AddToCart 4, 2
EXEC AddToCart 4, 3
EXEC AddToCart 4, 4
EXEC AddToCart 4, 5
GO

SELECT * FROM Cart
GO


EXEC RemoveFromCart 1, 1
GO

EXEC MakeOrder 1, 1
EXEC MakeOrder 1, 2
EXEC MakeOrder 2, 3
EXEC MakeOrder 2, 4
EXEC MakeOrder 3, 5
EXEC MakeOrder 3, 6
EXEC MakeOrder 4, 7
EXEC MakeOrder 4, 8
GO


SELECT * FROM Orders
GO

SELECT dbo.GetOrderItemsPriceSum(4)

INSERT OrderItems(OrderID, ProductID, OrderStatusID) VALUES (1, 2, 1)
INSERT OrderItems(OrderID, ProductID, OrderStatusID) VALUES (1, 3, 1)
INSERT OrderItems(OrderID, ProductID, OrderStatusID) VALUES (1, 4, 1)
INSERT OrderItems(OrderID, ProductID, OrderStatusID) VALUES (2, 5, 1)
INSERT OrderItems(OrderID, ProductID, OrderStatusID) VALUES (2, 6, 1)
INSERT OrderItems(OrderID, ProductID, OrderStatusID) VALUES (3, 2, 1)
INSERT OrderItems(OrderID, ProductID, OrderStatusID) VALUES (3, 2, 1)
INSERT OrderItems(OrderID, ProductID, OrderStatusID) VALUES (3, 5, 1)
INSERT OrderItems(OrderID, ProductID, OrderStatusID) VALUES (4, 3, 1)
INSERT OrderItems(OrderID, ProductID, OrderStatusID) VALUES (4, 4, 1)
GO

SELECT * FROM OrderItems
GO

SELECT * FROM OrderItems
WHERE OrderID = 4
GO

EXEC ChangeProductStatus 4, 3, 2

SELECT Orders.OrderID, Products.ProductID, Products.ProductName, Products.Quantity, Products.Price, OrderStatus.OrderStatusName
FROM OrderItems INNER JOIN Orders ON Orders.OrderID = OrderItems.OrderID
INNER JOIN Products ON Products.ProductID = OrderItems.ProductID
INNER JOIN OrderStatus ON OrderStatus.OrderStatusID = OrderItems.OrderStatusID
WHERE Orders.OrderID = 4
GO