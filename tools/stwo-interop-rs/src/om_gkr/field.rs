//! Oracle-only quadratic tower over the independently pinned Rust QM31.
//! Schoolbook outer multiplication deliberately differs from Zig Karatsuba.
use num_traits::{Num, One, Zero};
use std::{
    fmt,
    iter::{Product, Sum},
    ops::*,
};
use stwo::core::fields::{m31::M31, qm31::QM31, ComplexConjugate, ExtensionOf, Field, FieldExpOps};
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct O(pub QM31, pub QM31);
impl O {
    pub fn from_words(v: [u32; 8]) -> Self {
        Self(
            QM31::from_u32_unchecked(v[0], v[1], v[2], v[3]),
            QM31::from_u32_unchecked(v[4], v[5], v[6], v[7]),
        )
    }
    pub fn words(self) -> [u32; 8] {
        let a = self.0.to_m31_array();
        let b = self.1.to_m31_array();
        [
            a[0].0, a[1].0, a[2].0, a[3].0, b[0].0, b[1].0, b[2].0, b[3].0,
        ]
    }
    fn u() -> QM31 {
        QM31::from_u32_unchecked(0, 0, 1, 0)
    }
}
impl fmt::Display for O {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self.words())
    }
}
impl Zero for O {
    fn zero() -> Self {
        Self(QM31::zero(), QM31::zero())
    }
    fn is_zero(&self) -> bool {
        *self == Self::zero()
    }
}
impl One for O {
    fn one() -> Self {
        Self(QM31::one(), QM31::zero())
    }
}
impl Add for O {
    type Output = Self;
    fn add(self, b: Self) -> Self {
        Self(self.0 + b.0, self.1 + b.1)
    }
}
impl Sub for O {
    type Output = Self;
    fn sub(self, b: Self) -> Self {
        Self(self.0 - b.0, self.1 - b.1)
    }
}
impl Neg for O {
    type Output = Self;
    fn neg(self) -> Self {
        Self(-self.0, -self.1)
    }
}
impl Mul for O {
    type Output = Self;
    fn mul(self, b: Self) -> Self {
        Self(
            self.0 * b.0 + Self::u() * self.1 * b.1,
            self.0 * b.1 + self.1 * b.0,
        )
    }
}
impl FieldExpOps for O {
    fn inverse(&self) -> Self {
        assert!(!self.is_zero(), "zero oracle inverse");
        let n = (self.0 * self.0 - Self::u() * self.1 * self.1).inverse();
        Self(self.0 * n, -self.1 * n)
    }
}
impl Div for O {
    type Output = Self;
    fn div(self, b: Self) -> Self {
        self * b.inverse()
    }
}
impl Rem for O {
    type Output = Self;
    fn rem(self, _: Self) -> Self {
        panic!("oracle field remainder is unused")
    }
}
macro_rules! assign {($trait:ident,$method:ident,$op:tt)=>{impl $trait for O{fn $method(&mut self,b:Self){*self=*self $op b;}}};}
assign!(AddAssign,add_assign,+);
assign!(SubAssign,sub_assign,-);
assign!(MulAssign,mul_assign,*);
assign!(DivAssign,div_assign,/);
assign!(RemAssign,rem_assign,%);
impl Num for O {
    type FromStrRadixErr = std::num::ParseIntError;
    fn from_str_radix(s: &str, r: u32) -> Result<Self, Self::FromStrRadixErr> {
        Ok(Self::from(M31::from(u32::from_str_radix(s, r)?)))
    }
}
impl ComplexConjugate for O {
    fn complex_conjugate(&self) -> Self {
        Self(self.0, -self.1)
    }
}
impl Field for O {}
impl From<M31> for O {
    fn from(v: M31) -> Self {
        Self(QM31::from(v), QM31::zero())
    }
}
impl ExtensionOf<M31> for O {
    const EXTENSION_DEGREE: usize = 8;
}
macro_rules! base_ops {($trait:ident,$method:ident,$op:tt,$assign:ident,$amethod:ident)=>{impl $trait<M31> for O{type Output=Self;fn $method(self,b:M31)->Self{self $op Self::from(b)}}impl $assign<M31> for O{fn $amethod(&mut self,b:M31){*self=*self $op Self::from(b);}}};}
base_ops!(Add,add,+,AddAssign,add_assign);
base_ops!(Sub,sub,-,SubAssign,sub_assign);
base_ops!(Mul,mul,*,MulAssign,mul_assign);
base_ops!(Div,div,/,DivAssign,div_assign);
base_ops!(Rem,rem,%,RemAssign,rem_assign);
impl Product for O {
    fn product<I: Iterator<Item = Self>>(i: I) -> Self {
        i.fold(Self::one(), |a, b| a * b)
    }
}
impl<'a> Product<&'a Self> for O {
    fn product<I: Iterator<Item = &'a Self>>(i: I) -> Self {
        i.copied().product()
    }
}
impl Sum for O {
    fn sum<I: Iterator<Item = Self>>(i: I) -> Self {
        i.fold(Self::zero(), |a, b| a + b)
    }
}
impl<'a> Sum<&'a Self> for O {
    fn sum<I: Iterator<Item = &'a Self>>(i: I) -> Self {
        i.copied().sum()
    }
}
