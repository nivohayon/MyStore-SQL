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
OrderID nvarchar(30) PRIMARY KEY NOT NULL,
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
OrderID nvarchar(30) FOREIGN KEY REFERENCES Orders (OrderID) NOT NULL,
ProductID int FOREIGN KEY REFERENCES Products (ProductID) NOT NULL,
)
GO

CREATE TABLE Chats
(
ChatID int IDENTITY PRIMARY KEY,
UserOneID int FOREIGN KEY REFERENCES Users (UserID),
UserTwoID int FOREIGN KEY REFERENCES Users (UserID),
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


-- שינוי פורמט תאריך
Set DateFormat dmy
GO


-- הצפנת סיסמא
CREATE PROC HashPass(@pass nvarchar(255), @out varbinary(max) output)
AS
SET @out = HASHBYTES('SHA2_512', @pass)
GO

-- האם אימייל קיים
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

-- האם השם משתמש קיים
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
SELECT UserID, FirstName, LastName, Username, Email FROM Users WHERE UserID = @UserID
GO


-- קבלת שם משתמש לפי מזהה של משתמש
CREATE PROC GetUsernameById
(
@UserID int
)
AS
SELECT Username FROM Users
WHERE UserID = @UserID
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


-- האם הסיסמא החדשה שונה מהסיסמא הקיימת
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


-- שנה סיסמא
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
@UserTwoID int
)
AS
BEGIN TRANSACTION
IF EXISTS(SELECT ChatID FROM Chats WHERE UserOneID = @UserOneID AND UserTwoID = @UserTwoID)
BEGIN
SELECT 0
END
ELSE BEGIN
INSERT Chats(UserOneID, UserTwoID, CreatedOn) 
VALUES (@UserOneID, @UserTwoID, GETDATE())
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


-- מחזיר את כל הצאטים שהמשתמש נוכח בהם
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


-- מחזיר את כל ההודעות בצאט לפי מזהה של צאט
CREATE PROC GetAllRepliesByChatID
(
@ChatID int
)
AS
BEGIN TRANSACTION
SELECT * FROM Replies WHERE ChatID = @ChatID
ORDER BY TimeSent
IF @@ERROR<>0
BEGIN
	ROLLBACK TRANSACTION
	PRINT(@@ERROR)
	RETURN
END
COMMIT TRANSACTION
GO


-- בודק אם קיים צאט כבר
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


-- מחזיר את המזהה של הצאט לפי המשתתפים
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


-- הצגת כתובות לפי מזהה של משתמש
CREATE PROC GetAddressesByUserId
(@UserID int)
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


--עריכת מחיר מוצר
CREATE PROC EditProductPrice
(
@ProductID int,
@Price float
)
AS
BEGIN TRANSACTION
UPDATE Products SET Price = @Price
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


-- הצגת המוצר לפי המזהה
CREATE PROC GetProductById
(
@ProductID int
)
AS
SELECT * FROM Products WHERE ProductID = @ProductID
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


-- הצגת פריטים בעגלה לפי מזהה משתמש
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
@OrderID nvarchar(30),
@UserID int,
@AddressID int,
@Total float
)
AS
BEGIN TRANSACTION
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
INSERT Orders(OrderID, UserID, FirstName, LastName, AddressLine1, AddressLine2, City, CountryCode, ZipCode, PhoneNumber, Total, CreatedOn)
VALUES (@OrderID, @UserID, @FirstName, @LastName, @AddressLine1, @AddressLine2, @City, @CountryCode, @ZipCode, @PhoneNumber, @Total, GETDATE())
IF @@ERROR<>0
BEGIN
	ROLLBACK TRANSACTION
	PRINT(@@ERROR)
	RETURN
END
COMMIT TRANSACTION
GO


-- ניקוי עגלה אחרי שההזמנה שולמה בהצלחה
CREATE PROC ClearUserCart
(
@CartID int
)
AS
DELETE FROM Cart WHERE CartID = @CartID
GO


--הוספת מוצר להזמנה
CREATE PROC AddItemToOrder
(
@OrderID nvarchar(30),
@ProductID int
)
AS
BEGIN TRANSACTION
INSERT OrderItems(OrderID, ProductID) VALUES (@OrderID, @ProductID)
UPDATE Products SET IsHidden = 1 WHERE ProductID = @ProductID
IF @@ERROR<>0
BEGIN
	ROLLBACK TRANSACTION
	PRINT(@@ERROR)
	RETURN
END
COMMIT TRANSACTION
GO


--הצגת כל המוצרים בהזמנה לפי מזהה הזמנה
CREATE PROC GetOrderItems
(@OrderID nvarchar(30))
AS
SELECT Orders.OrderID, Products.ProductID, Products.UserID, Products.ProductName, (Products.Price + Products.ShippingCosts) AS 'Total', Products.ImagesSource, Orders.CreatedOn
FROM OrderItems INNER JOIN Orders ON Orders.OrderID = OrderItems.OrderID
INNER JOIN Products ON Products.ProductID = OrderItems.ProductID
WHERE Orders.OrderID = @OrderID
GO


--מחזירה את כל המזהים של ההזמנות לפי מזהה משתמש
CREATE PROC GetUserOrders
(@UserID int)
AS
SELECT * FROM Orders
WHERE UserID = @UserID
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


-- הוספת טריגרים


-- מעדכן את הזמן האחרון שנשלחה בו הודעה בצאט מסויים
CREATE TRIGGER T_LastSentMessage
ON Replies FOR INSERT
AS
UPDATE Chats
SET LastReplySentOn = GETDATE()
FROM Replies INNER JOIN inserted
ON Replies.ChatID = inserted.ChatID
WHERE Chats.ChatID = inserted.ChatID
GO


-- Reset Identity Field
DBCC CHECKIDENT ('TableName', RESEED, 0)


-- הזנת נתונים לטבלאות


-- כל הקטגוריות
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


-- כל התת קטגוריות


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


-- כל המצבי מוצר
INSERT Conditions(ConditionName) VALUES ('New In The Box')
INSERT Conditions(ConditionName) VALUES ('Like New')
INSERT Conditions(ConditionName) VALUES ('Used')
INSERT Conditions(ConditionName) VALUES ('Require Fixing')
INSERT Conditions(ConditionName) VALUES ('Irrelevant')
GO

SELECT * FROM Conditions
GO


-- כל המדינות
INSERT Countries(CountryName) VALUES ('Israel')
INSERT Countries(CountryName) VALUES ('Russia')
INSERT Countries(CountryName) VALUES ('Egypt')
INSERT Countries(CountryName) VALUES ('Greece')
INSERT Countries(CountryName) VALUES ('Belgium')
GO

SELECT * FROM Countries
GO


-- כל הסוגי מכירת מוצר
INSERT SellTypes(SellTypeName) VALUES ('Buy Now')
INSERT SellTypes(SellTypeName) VALUES ('Auction')
GO

SELECT * FROM SellTypes
GO


-- כל האופציות לאיזורי משלוח
INSERT ShipsToTypes(ShipsToTypeName) VALUES ('Worldwide')
INSERT ShipsToTypes(ShipsToTypeName) VALUES ('My Country Only')
INSERT ShipsToTypes(ShipsToTypeName) VALUES ('Contact Me')
GO

SELECT * FROM ShipsToTypes
GO


SELECT * FROM Chats


-- DROP ALL TABLES SEQUENCE

--DROP TABLE Replies
--GO
--DROP TABLE Chats
--GO
--DROP TABLE UserAddresses
--GO
--DROP TABLE OrderItems
--GO
--DROP TABLE Orders
--GO
--DROP TABLE Cart
--GO
--DROP TABLE Products
--GO
--DROP TABLE Users
--GO
--DROP TABLE SubCategories
--GO
--DROP TABLE Categories
--GO
--DROP TABLE Conditions
--GO
--DROP TABLE SellTypes
--GO
--DROP TABLE Countries
--GO
--DROP TABLE ShipsToTypes
--GO